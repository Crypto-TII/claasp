# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************
"""
Check that a cipher is an SPN and find its substitution layers and the linear layers between them.

Leaving out the key schedule, every round must be a substitution layer, made of S-boxes applied in parallel to the
whole state, followed only by affine operations (linear layer, key and constant additions). The S-boxes are S-box
components, or the rows of a chi-like layer of NOT / AND / XOR components, of at most 16 bits. Other ciphers raise
:class:`UnsupportedCipherError`, including SPNs whose nonlinear layer does not split into such S-boxes.

The linear layers are computed on first use, by evaluating the cipher with the S-boxes replaced by the identity and
the AND outputs set to 0. They do not include the key and constant additions, so they exist whatever the key
schedule.
"""
import copy
from dataclasses import dataclass
from functools import cached_property

import numpy as np
from sage.matrix.constructor import matrix
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF

from claasp.cipher_modules.evaluator import evaluate_vectorized
from claasp.editor import get_key_schedule_component_ids
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN,
                                  PERMUTATION_COMPONENT, SBOX, WORD_OPERATION)
from claasp.utils.utils import simplify_inputs

_AFFINE_OPERATIONS = (CONSTANT, LINEAR_LAYER, MIX_COLUMN, PERMUTATION_COMPONENT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                      "XOR", "NOT", "ROTATE", "SHIFT")
# S-boxes and AND (checked to form chi-like layers) are the only nonlinear operations
_SUPPORTED_OPERATIONS = _AFFINE_OPERATIONS + (SBOX, "AND")
_MAX_VIRTUAL_SBOX_SIZE = 16


class UnsupportedCipherError(ValueError):
    """
    Raised when :class:`SpnStructure` does not recognize a cipher as an SPN.
    """


@dataclass(frozen=True)
class SubstitutionLayer:
    """
    Substitution layer of one round.

    - ``round_number`` -- **integer**; the round of the cipher containing the layer
    - ``kind`` -- **string**; ``'sbox'`` (S-box components) or ``'chi'`` (NOT / AND / XOR components)
    - ``sources`` -- **tuple**; the state bits entering the layer, as ``(component_id, bit)`` pairs (for an
      S-box layer, the bits of its S-boxes; for a chi layer, the linear operands of the XOR components)
    - ``sboxes`` -- **tuple**; ``(positions, table)`` pairs, ``positions`` indexing ``sources`` with the
      most significant bit first
    - ``input_ids`` -- **frozenset**; ids of the components (or cipher inputs) the layer reads
    - ``output_ids`` -- **frozenset**; ids of the components holding the layer's output

    ``size`` is the number of state bits the layer covers. Layers are obtained from
    :attr:`SpnStructure.substitution_layers`.
    """
    round_number: int
    kind: str
    sources: tuple
    sboxes: tuple
    input_ids: frozenset
    output_ids: frozenset

    @property
    def size(self):
        return len(self.sources)


def _operation(component):
    """The word operation of ``component`` (``'XOR'``, ``'AND'``, ...), or its type for other components."""
    return component.description[0] if component.type == WORD_OPERATION else component.type


def _operands(component):
    """The input bits of ``component`` as ``(link, bit)`` pairs, split into operands of the output size."""
    bits = [(link, bit) for link, bits in zip(component.input_id_links, component.input_bit_positions) for bit in bits]
    size = component.output_bit_size
    return [bits[i * size:(i + 1) * size] for i in range(len(bits) // size)]


def _check_supported_components(components):
    """Raise :class:`UnsupportedCipherError` on components outside ``_SUPPORTED_OPERATIONS`` and on S-boxes
    whose input and output sizes differ."""
    for component in components:
        operation = _operation(component)
        if operation not in _SUPPORTED_OPERATIONS:
            raise UnsupportedCipherError(f"{component.id}: {operation} components are not supported")
        if component.type == SBOX and component.input_bit_size != component.output_bit_size:
            raise UnsupportedCipherError(
                f"{component.id}: S-boxes with different input and output sizes are not supported")


def _sbox_layer(round_number, sboxes):
    sources, groups = [], []
    for sbox in sboxes:
        m = sbox.input_bit_size
        groups.append((tuple(range(len(sources), len(sources) + m)), tuple(int(y) for y in sbox.description)))
        sources += [(sbox.id, bit) for bit in range(m)]
    return SubstitutionLayer(round_number, "sbox", tuple(sources), tuple(groups),
                             frozenset(link for sbox in sboxes for link in sbox.input_id_links),
                             frozenset(sbox.id for sbox in sboxes))


def _split_chi_xor(component, ands):
    """``(linear operand, AND operands)`` of a chi XOR, ``None`` for an XOR not fed by any AND."""
    operands = _operands(component)
    from_and = [all(link in ands for link, _ in operand) for operand in operands]
    if not any(from_and):
        return None
    linear = [operand for operand, is_and in zip(operands, from_and) if not is_and]
    if len(linear) != 1 or any(link in ands for link, _ in linear[0]):
        raise UnsupportedCipherError(f"{component.id}: expected one linear operand XOR AND terms (chi-like layer)")
    return linear[0], [operand for operand, is_and in zip(operands, from_and) if is_and]


def _chi_outputs(round_number, components, ands):
    """Sources (linear operands), AND bits of every output bit, and ids of the chi XORs of a round."""
    sources, terms, chi_xors = [], [], set()
    for component in components:
        split = _split_chi_xor(component, ands) if _operation(component) == "XOR" else None
        if split is None:
            continue
        linear, and_operands = split
        chi_xors.add(component.id)
        sources += linear
        terms += [[operand[bit] for operand in and_operands] for bit in range(component.output_bit_size)]
    if not sources:
        raise UnsupportedCipherError(f"round {round_number}: AND components outside a chi-like layer")
    if len(set(sources)) != len(sources):
        raise UnsupportedCipherError(f"round {round_number}: a bit is the linear operand of two chi outputs")
    return sources, terms, chi_xors


def _literal(bit, nots, index, round_number):
    """``(source index, flip)`` of an AND input bit, ``flip = 1`` when it goes through a NOT."""
    link, position = bit
    flip = 0
    if link in nots:
        link, position = _operands(nots[link])[0][position]
        flip = 1
    if (link, position) not in index:
        raise UnsupportedCipherError(f"round {round_number}: AND input {bit} is not a bit entering the chi layer")
    return index[(link, position)], flip


def _dependency_groups(formulas):
    """Connected components of the output bits linked by the literals of their AND terms."""
    from sage.graphs.graph import Graph

    graph = Graph([range(len(formulas)), [(i, j) for i, formula in enumerate(formulas)
                                          for term in formula for j, _ in term if j != i]], format="vertices_and_edges")
    return sorted(sorted(component) for component in graph.connected_components())


def _chi_output_bit(x, local, i, formulas):
    value = x[local[i]]
    for term in formulas[i]:
        value ^= int(all(x[local[j]] ^ flip for j, flip in term))
    return value


def _virtual_sbox_table(positions, formulas):
    m = len(positions)
    local = {i: k for k, i in enumerate(positions)}
    table = []
    for word in range(2 ** m):
        x = [(word >> (m - 1 - k)) & 1 for k in range(m)]
        y = 0
        for i in positions:
            y = (y << 1) | _chi_output_bit(x, local, i, formulas)
        table.append(y)
    return tuple(table)


def _virtual_sboxes(formulas, round_number):
    groups = []
    for positions in _dependency_groups(formulas):
        if len(positions) > _MAX_VIRTUAL_SBOX_SIZE:
            raise UnsupportedCipherError(f"round {round_number}: virtual S-box of {len(positions)} bits "
                                         f"(at most {_MAX_VIRTUAL_SBOX_SIZE} supported)")
        groups.append((tuple(positions), _virtual_sbox_table(positions, formulas)))
    return tuple(groups)


def _chi_layer(round_number, components):
    by_id = {c.id: c for c in components}
    ands = {c.id for c in components if _operation(c) == "AND"}
    nots = {c.id: c for c in components if _operation(c) == "NOT"}
    sources, terms, chi_xors = _chi_outputs(round_number, components, ands)
    index = {source: i for i, source in enumerate(sources)}
    # per output bit: AND terms, each a list of (source index, flip)
    formulas = [[[_literal(operand[position], nots, index, round_number) for operand in _operands(by_id[link])]
                 for link, position in bit_terms] for bit_terms in terms]
    return SubstitutionLayer(round_number, "chi", tuple(sources), _virtual_sboxes(formulas, round_number),
                             frozenset(link for link, _ in sources), frozenset(chi_xors))


def _round_layer(round_number, components):
    """The substitution layer of a round, ``None`` if it has none."""
    sboxes = [c for c in components if c.type == SBOX]
    has_and = any(_operation(c) == "AND" for c in components)
    if sboxes and has_and:
        raise UnsupportedCipherError(f"round {round_number} mixes S-box and AND components")
    if sboxes:
        return _sbox_layer(round_number, sboxes)
    if has_and:
        return _chi_layer(round_number, components)
    return None


def _check_and_outputs_feed_chi_xors(components, chi_xors):
    ands = {c.id for c in components if _operation(c) == "AND"}
    for component in components:
        if component.id not in chi_xors and any(link in ands for link in component.input_id_links):
            raise UnsupportedCipherError(f"{component.id}: uses an AND output outside a chi-like layer")


def _state_input(cipher, key_schedule_ids):
    """Index of the state input: the only input that is not a key or tweak input."""
    indices = [i for i, name in enumerate(cipher.inputs) if name not in key_schedule_ids]
    if len(indices) != 1:
        raise UnsupportedCipherError(f"expected one state input besides the key and tweak inputs, found "
                                     f"{[cipher.inputs[i] for i in indices]}")
    return indices[0]


def _check_layer_sizes(cipher, layers, state_index):
    if not layers:
        raise UnsupportedCipherError("no round has a substitution layer")
    state_size = layers[0].size
    if any(layer.size != state_size for layer in layers):
        raise UnsupportedCipherError("substitution layers of different sizes: partial substitution layers are not "
                                     "supported")
    if cipher.inputs_bit_size[state_index] != state_size:
        raise UnsupportedCipherError(f"the substitution layers cover {state_size} bits but the state input "
                                     f"{cipher.inputs[state_index]} has {cipher.inputs_bit_size[state_index]} bits")
    return state_size


def _upstream(by_id, links, stop):
    """Every link reached walking back from ``links`` through the components, not going past ``stop``."""
    stack, seen = list(links), set(stop)
    while stack:
        link = stack.pop()
        yield link
        if link in by_id and link not in seen:  # cipher inputs and constants' empty link have no inputs
            seen.add(link)
            stack.extend(by_id[link].input_id_links)


def _check_layer_boundaries(cipher, layers, state_input):
    """
    Raise unless every substitution layer is a parallel layer reading the state only through the previous one.

    Walking back from the inputs of a layer, down to the outputs of the previous layer: reaching one of
    the layer's own outputs means its components are applied one after the other (not in parallel);
    reaching the state input means the previous layer is bypassed. Either way the round is not one layer of
    S-boxes applied to the whole state.
    """
    by_id = {component.id: component for component in cipher.all_components()}
    for previous, layer in zip([None] + layers, layers):
        for link in _upstream(by_id, layer.input_ids, previous.output_ids if previous else ()):
            if link in layer.output_ids:
                raise UnsupportedCipherError(f"round {layer.round_number}: an input of the substitution layer "
                                             f"depends on one of its outputs (components not applied in parallel)")
            if previous and link == state_input:
                raise UnsupportedCipherError(f"round {layer.round_number}: the substitution layer depends on the "
                                             f"state through a path avoiding the substitution layer of round "
                                             f"{previous.round_number}")


def _check_two_layers(layers):
    if len(layers) < 2:
        raise UnsupportedCipherError(f"at least two rounds with a substitution layer are needed, found {len(layers)}")


def _force_and_to_zero(components, component, round_number):
    """AND(x, 0, ...) = 0 on every evaluation path (the vectorized AND ignores the description)."""
    from claasp.components.constant_component import Constant

    size = component.output_bit_size
    zero = Constant(round_number, len(components), size, 0)  # a fresh index gives a fresh id
    components.insert(components.index(component), zero)
    operands = _operands(component)
    bits = operands[0] + [(zero.id, bit) for bit in range(size)] + [bit for operand in operands[2:] for bit in operand]
    links, positions = simplify_inputs([link for link, _ in bits], [[bit] for _, bit in bits])
    component.input_id_links = links
    component.input_bit_positions = positions


def _linearize_cipher(cipher):
    """
    A copy of ``cipher`` with every S-box replaced by the identity and every AND component `AND(x, y, ...)`
    turned into `AND(x, 0, ...)`, so that a chi-like XOR `s_i + AND(...)` becomes the identity on `s_i`.
    """
    linear_cipher = copy.deepcopy(cipher)
    for round_number in range(linear_cipher.number_of_rounds):
        components = linear_cipher.rounds.components_in_round(round_number)
        for component in list(components):
            if component.type == SBOX:
                component.description = list(range(2 ** component.input_bit_size))
            elif _operation(component) == "AND":
                _force_and_to_zero(components, component, round_number)
    return linear_cipher


def _unit_vector_samples(cipher, input_indices):
    """0 (all inputs at 0), then every unit vector of the inputs ``input_indices`` (MSB first), as lists of integers."""
    sizes = cipher.inputs_bit_size
    samples = [[0] * len(sizes)]
    for input_index in input_indices:
        for bit in range(sizes[input_index]):
            sample = [0] * len(sizes)
            sample[input_index] = 1 << (sizes[input_index] - 1 - bit)
            samples.append(sample)
    return samples


def _source_bits(cipher, samples, sources):
    """Value of every source bit for every sample, from one vectorized evaluation of ``cipher``."""
    inputs = [[sample[index] for sample in samples] for index in range(len(cipher.inputs))]
    values = evaluate_vectorized(cipher, inputs, evaluate_api=True, component_outputs=True)
    sizes = dict(zip(cipher.inputs, cipher.inputs_bit_size))
    sizes.update((component.id, component.output_bit_size) for component in cipher.all_components())
    bits = {}
    for link, position in set(sources):
        array = values[link]  # big-endian bytes of the value, right-aligned, one column per sample
        shift = sizes[link] - 1 - position
        row = (array[array.shape[0] - 1 - shift // 8] >> (shift % 8)) & 1
        bits[(link, position)] = np.broadcast_to(row, (len(samples),))  # constants have a single column
    return bits


def _layer_maps(cipher, layers, input_indices):
    """
    For every layer, ``(A, b)`` with `s = A x + b` in the linearized cipher, where `s` is the bits entering the
    layer and `x` the inputs ``input_indices`` concatenated, the other inputs being 0.
    """
    samples = _unit_vector_samples(cipher, input_indices)
    sources = [source for layer in layers for source in layer.sources]
    bits = _source_bits(_linearize_cipher(cipher), samples, sources)
    F = GF(2)
    maps = []
    for layer in layers:
        layer_bits = np.array([bits[source] for source in layer.sources], dtype=np.uint8)
        offset = layer_bits[:, 0]
        linear = matrix(F, layer.size, len(samples) - 1, (layer_bits[:, 1:] ^ offset[:, None]).tolist())
        maps.append((linear, vector(F, offset.tolist())))
    return maps


def _between_layers(state_input, layers, maps):
    """
    `\\Lambda_{r+1} \\Lambda_r^{-1}` for consecutive layers, where `\\Lambda_r` maps the state input to the input of
    layer `r`; raises if some `\\Lambda_r` is not invertible.
    """
    for layer, linear in zip(layers, maps):
        if not linear.is_invertible():
            raise UnsupportedCipherError(f"the map from {state_input} to the substitution layer of round "
                                         f"{layer.round_number} is not invertible")
    result = []
    for current, following in zip(maps, maps[1:]):
        linear = following * current.inverse()
        linear.set_immutable()
        result.append(linear)
    return result


class SpnStructure:
    """
    The SPN structure of ``cipher``: checks that every round is a substitution layer followed by affine operations,
    and gives the substitution layers and the linear layers between them.

    Building the object only reads the component graph, leaving out the key schedule, and raises
    :class:`UnsupportedCipherError` unless:

    - every component outside the key schedule is an S-box, a NOT / AND / XOR / rotation / shift, a linear
      layer, a mix column, a permutation, a constant or an output, and every AND belongs to a chi-like layer;
    - every round has at most one substitution layer (S-boxes, or chi-like with rows of at most 16 bits, not
      both), at least one round has one, and all of them cover the state input (the only input that is not a
      key or tweak input);
    - the components of every substitution layer are applied in parallel (none depends on another one's
      output), and every substitution layer sees the state only through the previous one (no bypass).

    The cipher is copied when the object is built, so later changes to ``cipher`` are not seen. The linear layers
    are computed on first access to :attr:`linear_layers` (one vectorized evaluation).

    INPUT:

    - ``cipher`` -- **Cipher object**; a cipher instance

    EXAMPLES:

    Keccak written with NOT / AND / XOR: the chi rows become 5-bit S-boxes, equal to Keccak's S-box::

        sage: from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
        sage: from claasp.ciphers.permutations.keccak_sbox_permutation import SBOX
        sage: from claasp.cipher_modules.spn_structure import SpnStructure
        sage: structure = SpnStructure(KeccakPermutation(number_of_rounds=2, word_size=4))
        sage: [(layer.kind, len(layer.sboxes)) for layer in structure.substitution_layers]
        [('chi', 20), ('chi', 20)]
        sage: all(table == tuple(SBOX) for _, table in structure.substitution_layers[0].sboxes)
        True

    AES: the key is the first input and the S-boxes of the key schedule are left out; the linear layer between the
    two substitution layers (ShiftRows, then MixColumns) is an invertible `128 \\times 128` matrix::

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: structure = SpnStructure(AESBlockCipher(number_of_rounds=2))
        sage: structure.state_input, structure.key_size, [len(layer.sboxes) for layer in structure.substitution_layers]
        ('plaintext', 128, [16, 16])
        sage: [(linear.dimensions(), linear.is_invertible()) for linear in structure.linear_layers]
        [((128, 128), True)]
    """

    def __init__(self, cipher):
        cipher = copy.deepcopy(cipher)  # later changes to the caller's cipher must not affect the structure
        key_schedule_ids = set(get_key_schedule_component_ids(cipher))
        state_index = _state_input(cipher, key_schedule_ids)
        data_path = [component for component in cipher.all_components() if component.id not in key_schedule_ids]
        _check_supported_components(data_path)
        layers = [_round_layer(round_number, [c for c in cipher.rounds.components_in_round(round_number)
                                              if c.id not in key_schedule_ids])
                  for round_number in range(cipher.number_of_rounds)]
        layers = [layer for layer in layers if layer is not None]
        _check_and_outputs_feed_chi_xors(data_path, {i for layer in layers if layer.kind == "chi"
                                                     for i in layer.output_ids})
        self._state_size = _check_layer_sizes(cipher, layers, state_index)
        _check_layer_boundaries(cipher, layers, cipher.inputs[state_index])
        self._cipher = cipher
        self._state_index = state_index
        self._layers = tuple(layers)

    @property
    def substitution_layers(self):
        """The :class:`SubstitutionLayer` of every round having one, in round order."""
        return self._layers

    @property
    def state_input(self):
        """The name of the state input: the only input that is not a key or tweak input."""
        return self._cipher.inputs[self._state_index]

    @property
    def state_size(self):
        """The size `n` of the state, i.e. of the state input and of every substitution layer."""
        return self._state_size

    @property
    def key_size(self):
        """The total size of the other inputs (key, tweak, ...), `0` for a permutation."""
        return sum(size for i, size in enumerate(self._cipher.inputs_bit_size) if i != self._state_index)

    @cached_property
    def linear_layers(self):
        """
        The linear layers between consecutive substitution layers: ``linear_layers[i]`` is the `n \\times n` matrix
        `L_i` over `GF(2)` taking the output of ``substitution_layers[i]`` to the input of
        ``substitution_layers[i + 1]``, without the key and constant additions. What comes before the first or after
        the last substitution layer is not included.

        Computed on first access, from one vectorized evaluation of the cipher with the S-boxes replaced by the
        identity and the AND outputs set to 0, on 0 and on every unit vector of the state input. Raises
        :class:`UnsupportedCipherError` if there are fewer than two substitution layers or if the state input does
        not reach some substitution layer bijectively.
        """
        _check_two_layers(self._layers)
        maps = [linear for linear, _ in _layer_maps(self._cipher, self._layers, [self._state_index])]
        return tuple(_between_layers(self.state_input, self._layers, maps))
