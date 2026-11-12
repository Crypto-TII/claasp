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
Check that a cipher is an SPN and find its substitution layers and the linear layer following each of them.

Leaving out the key schedule, every round must be either a substitution layer, made of S-boxes applied in parallel
to the whole state, followed only by affine operations (linear layer, key and constant additions), or affine
operations only. The S-boxes are S-box components, or the rows of a chi-like layer of NOT / AND / XOR components, of
at most 16 bits. Other ciphers raise :class:`UnsupportedCipherError`, including SPNs whose nonlinear layer does not
split into such S-boxes.

The linear layers are computed on first use, by evaluating the cipher with the S-boxes replaced by the identity and
the AND outputs set to 0. They do not include the key and constant additions, so they exist whatever the key
schedule.
"""
import copy
from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple

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
_MAX_CHI_SBOX_SIZE = 16


class UnsupportedCipherError(ValueError):
    """
    Raised when :class:`SpnStructure` does not recognize a cipher as an SPN, or when the linear layers (or affine
    parts) of a recognized one cannot be computed.
    """


def _bits_text(links, positions):
    """``xor_0_1[0..7]``-style text for CLAASP input links and bit positions."""
    parts = []
    for link, bits in zip(links, positions):
        consecutive = len(bits) > 1 and list(bits) == list(range(bits[0], bits[-1] + 1))
        parts.append(f"{link}[{bits[0]}..{bits[-1]}]" if consecutive else f"{link}{list(bits)}")
    return ", ".join(parts)


class Sbox(NamedTuple):
    """
    One S-box of a substitution layer.

    - ``positions`` -- **tuple**; the state positions it reads and writes, most significant bit first
    - ``table`` -- **tuple**; its lookup table
    - ``input_id_link``, ``input_bit_positions`` -- **tuple**; the cipher bits it reads, in the format of a
      component's inputs
    - ``output_id_link``, ``output_bit_positions`` -- **tuple**; the cipher bits holding its output, in the same format
    """
    positions: tuple
    table: tuple
    input_id_link: tuple
    input_bit_positions: tuple
    output_id_link: tuple
    output_bit_positions: tuple

    def __repr__(self):
        table = ", ".join(str(value) for value in self.table[:8]) + (", ..." if len(self.table) > 8 else "")
        return (f"Sbox(positions={self.positions}, input={_bits_text(self.input_id_link, self.input_bit_positions)}, "
                f"output={_bits_text(self.output_id_link, self.output_bit_positions)}, table=({table}))")


def _sbox(positions, table, inputs, outputs):
    """An :class:`Sbox` from its positions, table, and input / output bits as ``(component_id, bit)`` pairs."""
    input_links, input_positions = simplify_inputs([link for link, _ in inputs], [[bit] for _, bit in inputs])
    output_links, output_positions = simplify_inputs([link for link, _ in outputs], [[bit] for _, bit in outputs])
    return Sbox(tuple(positions), tuple(table), tuple(input_links), tuple(tuple(bits) for bits in input_positions),
                tuple(output_links), tuple(tuple(bits) for bits in output_positions))


@dataclass(frozen=True)
class SubstitutionLayer:
    """
    Substitution layer of one round.

    - ``round_number`` -- **integer**; the round of the cipher containing the layer
    - ``kind`` -- **string**; ``'sbox'`` (S-box components) or ``'chi'`` (NOT / AND / XOR components)
    - ``input_bits`` -- **tuple**; ``input_bits[j]`` is the cipher bit, as a ``(component_id, bit)`` pair, entering
      the layer at state position ``j``
    - ``output_bits`` -- **tuple**; ``output_bits[j]`` is the cipher bit leaving the layer at state position ``j``
    - ``sboxes`` -- **tuple**; one :class:`Sbox` per S-box: its positions, its table, and the cipher bits it reads
      and writes

    State positions are the layer's own numbering of the state, not the bit numbering of the plaintext or of the
    cipher's specification; ``positions`` of the S-boxes and the rows and columns of
    :attr:`SpnStructure.linear_layers` use it. ``size`` is the number of state bits the layer covers. Layers are
    obtained from :attr:`SpnStructure.substitution_layers`.
    """
    round_number: int
    kind: str
    input_bits: tuple
    output_bits: tuple
    sboxes: tuple

    @property
    def size(self):
        return len(self.input_bits)

    def __repr__(self):
        sizes = "/".join(str(size) for size in sorted({len(sbox.positions) for sbox in self.sboxes}))
        tables = len({sbox.table for sbox in self.sboxes})
        return (f"SubstitutionLayer(round {self.round_number}, {self.kind}: {len(self.sboxes)} S-boxes of {sizes} bits "
                f"on {self.size} bits, {tables} distinct table{'s' if tables > 1 else ''})")


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
    inputs, outputs, groups = [], [], []
    for sbox in sboxes:
        m = sbox.input_bit_size
        positions = range(len(inputs), len(inputs) + m)
        inputs += _operands(sbox)[0]
        outputs += [(sbox.id, bit) for bit in range(m)]
        groups.append(_sbox(positions, (int(y) for y in sbox.description), inputs[-m:], outputs[-m:]))
    return (SubstitutionLayer(round_number, "sbox", tuple(inputs), tuple(outputs), tuple(groups)),
            frozenset(link for sbox in sboxes for link in sbox.input_id_links), frozenset(sbox.id for sbox in sboxes))


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


def _chi_sbox_table(positions, formulas):
    """Table of the chi output bits ``positions``: bit `i` is `x_i` plus the AND terms of ``formulas[i]``."""
    m = len(positions)
    local = {i: k for k, i in enumerate(positions)}
    table = []
    for word in range(2 ** m):
        x = [(word >> (m - 1 - k)) & 1 for k in range(m)]
        y = 0
        for i in positions:
            bit = x[local[i]]
            for term in formulas[i]:
                bit ^= int(all(x[local[j]] ^ flip for j, flip in term))
            y = (y << 1) | bit
        table.append(y)
    return tuple(table)


def _chi_sboxes(formulas, round_number, sources, outputs):
    """One S-box per group of output bits linked by their AND terms (connected components)."""
    from sage.graphs.graph import Graph

    graph = Graph([range(len(formulas)), [(i, j) for i, formula in enumerate(formulas)
                                          for term in formula for j, _ in term if j != i]], format="vertices_and_edges")
    groups = []
    for positions in sorted(sorted(component) for component in graph.connected_components()):
        if len(positions) > _MAX_CHI_SBOX_SIZE:
            raise UnsupportedCipherError(f"round {round_number}: a chi row of {len(positions)} bits "
                                         f"(at most {_MAX_CHI_SBOX_SIZE} supported)")
        groups.append(_sbox(positions, _chi_sbox_table(positions, formulas), [sources[p] for p in positions],
                            [outputs[p] for p in positions]))
    return tuple(groups)


def _chi_layer(round_number, components):
    by_id = {c.id: c for c in components}
    ands = {c.id for c in components if _operation(c) == "AND"}
    nots = {c.id: c for c in components if _operation(c) == "NOT"}
    # sources: linear operands of the chi XORs; outputs: the XOR output bit of each; terms: its AND bits
    sources, outputs, terms, chi_xors = [], [], [], set()
    for component in components:
        split = _split_chi_xor(component, ands) if _operation(component) == "XOR" else None
        if split is None:
            continue
        linear, and_operands = split
        chi_xors.add(component.id)
        sources += linear
        outputs += [(component.id, bit) for bit in range(component.output_bit_size)]
        terms += [[operand[bit] for operand in and_operands] for bit in range(component.output_bit_size)]
    if not sources:
        raise UnsupportedCipherError(f"round {round_number}: AND components outside a chi-like layer")
    if len(set(sources)) != len(sources):
        raise UnsupportedCipherError(f"round {round_number}: a bit is the linear operand of two chi outputs")
    index = {source: i for i, source in enumerate(sources)}
    # per output bit: AND terms, each a list of (source index, flip)
    formulas = [[[_literal(operand[position], nots, index, round_number) for operand in _operands(by_id[link])]
                 for link, position in bit_terms] for bit_terms in terms]
    return (SubstitutionLayer(round_number, "chi", tuple(sources), tuple(outputs),
                              _chi_sboxes(formulas, round_number, sources, outputs)),
            frozenset(link for link, _ in sources), frozenset(chi_xors))


def _round_layer(round_number, components):
    """
    The substitution layer of a round with the ids it reads and the ids holding its output, ``None`` if it has none.
    """
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


def _cipher_output(cipher):
    return [component for component in cipher.all_components() if component.type == CIPHER_OUTPUT][-1]


def _check_layer_boundaries(cipher, found, state_input):
    """
    Raise unless every substitution layer is a parallel layer reading the state only through the previous one, and
    the cipher output reads it only through the last one. ``found`` lists ``(layer, ids it reads, ids holding its
    output)`` in round order.

    Walking back from the inputs of a layer, down to the outputs of the previous layer: reaching one of
    the layer's own outputs means its components are applied one after the other (not in parallel);
    reaching the state input means the previous layer is bypassed. Either way the round is not one layer of
    S-boxes applied to the whole state.
    """
    by_id = {component.id: component for component in cipher.all_components()}
    boundaries = found + [(None, _cipher_output(cipher).input_id_links, ())]  # the output, checked like a layer
    for previous, (layer, reads, outputs) in zip([None] + found, boundaries):
        stack, seen = list(reads), set(previous[2] if previous else ())  # stop at the previous layer's outputs
        while stack:
            link = stack.pop()
            if link in by_id and link not in seen:  # cipher inputs and constants' empty link have no inputs
                seen.add(link)
                stack.extend(by_id[link].input_id_links)
            if link in outputs:
                raise UnsupportedCipherError(f"round {layer.round_number}: an input of the substitution layer "
                                             f"depends on one of its outputs (components not applied in parallel)")
            if previous and link == state_input:
                target = f"round {layer.round_number}: the substitution layer" if layer else "the cipher output"
                raise UnsupportedCipherError(f"{target} depends on the state through a path avoiding the "
                                             f"substitution layer of round {previous[0].round_number}")


def _linearize_cipher(cipher):
    """
    A copy of ``cipher`` with every S-box replaced by the identity and every AND component `AND(x, y, ...)`
    turned into `AND(x, 0, ...)`, so that a chi-like XOR `s_i + AND(...)` becomes the identity on `s_i`. The
    second operand is rewired to a 0 constant, since the vectorized AND ignores the description.
    """
    from claasp.components.constant_component import Constant

    linear_cipher = copy.deepcopy(cipher)
    for round_number in range(linear_cipher.number_of_rounds):
        components = linear_cipher.rounds.components_in_round(round_number)
        for component in list(components):
            if component.type == SBOX:
                component.description = list(range(2 ** component.input_bit_size))
            elif _operation(component) == "AND":
                size = component.output_bit_size
                zero = Constant(round_number, len(components), size, 0)  # a fresh index gives a fresh id
                components.insert(components.index(component), zero)
                operands = _operands(component)
                bits = operands[0] + [(zero.id, bit) for bit in range(size)] + sum(operands[2:], [])
                links, positions = simplify_inputs([link for link, _ in bits], [[bit] for _, bit in bits])
                component.input_id_links, component.input_bit_positions = links, positions
    return linear_cipher


def _layer_maps(cipher, layers, input_indices):
    """
    For every layer, then for the cipher output, ``(A, b)`` with `s = A x + b` in the linearized cipher, where `s`
    is the bits entering the layer (or the output) and `x` the inputs ``input_indices`` concatenated, the other
    inputs being 0. The bits are read at the layer's output, which equals its input once the S-boxes are the identity
    and the AND outputs are 0.
    """
    sizes = cipher.inputs_bit_size
    unit_vectors = [(index, 1 << (sizes[index] - 1 - bit)) for index in input_indices for bit in range(sizes[index])]
    # one sample at 0, then one per unit vector; the value of x on sample i + 1 is e_i
    inputs = [[0] + [value if index == i else 0 for index, value in unit_vectors] for i in range(len(sizes))]
    linear_cipher = _linearize_cipher(cipher)
    values = evaluate_vectorized(linear_cipher, inputs, evaluate_api=True, component_outputs=True)
    output = _cipher_output(cipher)
    targets = [layer.output_bits for layer in layers] + [[(output.id, bit) for bit in range(output.output_bit_size)]]
    output_sizes = {component.id: component.output_bit_size for component in linear_cipher.all_components()}
    # values[id]: big-endian bytes of the output, right-aligned, one column per sample
    bits = {link: np.unpackbits(values[link], axis=0)[-output_sizes[link]:]
            for link in {link for target in targets for link, _ in target}}
    F = GF(2)
    maps = []
    for target in targets:
        target_bits = np.array([bits[link][position] for link, position in target], dtype=np.uint8)
        offset = target_bits[:, 0]
        linear = matrix(F, len(target), len(unit_vectors), (target_bits[:, 1:] ^ offset[:, None]).tolist())
        maps.append((linear, vector(F, offset.tolist())))
    return maps


def _between_layers(state_input, layers, maps):
    """
    `\\Lambda_{r+1} \\Lambda_r^{-1}` for consecutive layers, then for the last layer and the output, where `\\Lambda_r`
    maps the state input to the input of layer `r`; raises if some `\\Lambda_r` is not invertible.
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
    The SPN structure of ``cipher``: checks that every round is a substitution layer followed by affine operations
    or affine operations only,
    and gives the substitution layers and the linear layer following each of them.

    Building the object only reads the component graph, leaving out the key schedule, and raises
    :class:`UnsupportedCipherError` unless:

    - every component outside the key schedule is an S-box, a NOT / AND / XOR / rotation / shift, a linear
      layer, a mix column, a permutation, a constant or an output, and every AND belongs to a chi-like layer;
    - every round has at most one substitution layer (S-boxes, or chi-like with rows of at most 16 bits, not
      both), at least one round has one, and all of them cover the state input (the only input that is not a
      key or tweak input);
    - the components of every substitution layer are applied in parallel (none depends on another one's
      output), every substitution layer sees the state only through the previous one, and the cipher output
      only through the last one (no bypass).

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
        sage: structure.substitution_layers[0]
        SubstitutionLayer(round 0, chi: 20 S-boxes of 5 bits on 100 bits, 1 distinct table)
        sage: all(sbox.table == tuple(SBOX) for sbox in structure.substitution_layers[0].sboxes)
        True

    AES: the key is the first input and the S-boxes of the key schedule are left out. The linear layer of the first
    round is ShiftRows then MixColumns; the last round has no MixColumns, so its linear layer is ShiftRows alone, a
    permutation matrix (one 1 per row)::

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: from claasp.cipher_modules.spn_structure import SpnStructure
        sage: structure = SpnStructure(AESBlockCipher(number_of_rounds=2))
        sage: structure
        SpnStructure(aes_block_cipher_k128_p128_o128_r2, 2 layers of 16 8-bit S-boxes, state plaintext, key 128 bits)
        sage: structure.substitution_layers[0]
        SubstitutionLayer(round 0, sbox: 16 S-boxes of 8 bits on 128 bits, 1 distinct table)
        sage: sbox = structure.substitution_layers[0].sboxes[0]
        sage: sbox.input_id_link, sbox.input_bit_positions, sbox.output_id_link
        (('xor_0_24',), ((0, 1, 2, 3, 4, 5, 6, 7),), ('sbox_0_25',))
        sage: [(layer.round_number, L.dimensions(), L.is_invertible(), len(L.nonzero_positions()))
        ....:  for layer, L in zip(structure.substitution_layers, structure.linear_layers)]
        [(0, (128, 128), True, 736), (1, (128, 128), True, 128)]
    """

    def __init__(self, cipher):
        cipher = copy.deepcopy(cipher)  # later changes to the caller's cipher must not affect the structure
        key_schedule_ids = set(get_key_schedule_component_ids(cipher))
        state_index = _state_input(cipher, key_schedule_ids)
        data_path = [component for component in cipher.all_components() if component.id not in key_schedule_ids]
        _check_supported_components(data_path)
        found = [_round_layer(round_number, [c for c in cipher.rounds.components_in_round(round_number)
                                             if c.id not in key_schedule_ids])
                 for round_number in range(cipher.number_of_rounds)]
        found = [triple for triple in found if triple is not None]
        layers = [layer for layer, _, _ in found]
        _check_and_outputs_feed_chi_xors(data_path, {i for layer, _, outputs in found if layer.kind == "chi"
                                                     for i in outputs})
        self._state_size = _check_layer_sizes(cipher, layers, state_index)
        _check_layer_boundaries(cipher, found, cipher.inputs[state_index])
        self._cipher = cipher
        self._state_index = state_index
        self._layers = tuple(layers)

    def __repr__(self):
        layers = self._layers
        counts = "/".join(str(count) for count in sorted({len(layer.sboxes) for layer in layers}))
        sizes = "/".join(str(size)
                         for size in sorted({len(sbox.positions) for layer in layers for sbox in layer.sboxes}))
        inputs = zip(self._cipher.inputs, self._cipher.inputs_bit_size)
        others = ", ".join(f"{name} {size} bits" for i, (name, size) in enumerate(inputs) if i != self._state_index)
        return (f"SpnStructure({self._cipher.id}, {len(layers)} layer{'s' if len(layers) > 1 else ''} of {counts} "
                f"{sizes}-bit S-boxes, state {self.state_input}, {others or 'no key'})")

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
        """The total size of the other inputs (key and tweak together), `0` for a permutation."""
        return sum(size for i, size in enumerate(self._cipher.inputs_bit_size) if i != self._state_index)

    @cached_property
    def linear_layers(self):
        """
        The linear layer following each substitution layer: ``linear_layers[r]`` is the matrix `L_r` over `GF(2)`
        taking the output of ``substitution_layers[r]`` to the input of ``substitution_layers[r + 1]``, or to the
        cipher output for the last one, without the key and constant additions. It is `n \\times n`, except for the
        last one when the output is not `n` bits. What comes before the first substitution layer is not included.

        Vectors are columns: ``L[j, i] == 1`` means that output bit ``i`` of ``substitution_layers[r]`` is added to
        input bit ``j`` of ``substitution_layers[r + 1]``, both in the layers' state positions (for the last one,
        ``j`` is the bit of the cipher output). ``L`` describes the values of the bits (an XOR-linear map), not how
        differences or masks propagate through the S-boxes. The last round of a cipher often differs from the others
        (no MixColumns in AES, only a key addition in PRESENT), and so does its linear layer.

        Computed on first access, from one vectorized evaluation of the cipher with the S-boxes replaced by the
        identity and the AND outputs set to 0, on 0 and on every unit vector of the state input. Raises
        :class:`UnsupportedCipherError` if the state input does not reach some substitution layer bijectively.

        EXAMPLES:

        In AES, the first output bit of the first S-box reaches 11 input bits of the next substitution layer, in its
        first four S-boxes (one column of MixColumns)::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.spn_structure import SpnStructure
            sage: structure = SpnStructure(AESBlockCipher(number_of_rounds=2))
            sage: layers, L = structure.substitution_layers, structure.linear_layers[0]
            sage: L.nonzero_positions_in_column(0)
            [3, 4, 6, 7, 8, 16, 24, 27, 28, 30, 31]
            sage: sorted({i for j in L.nonzero_positions_in_column(0) for i, sbox in enumerate(layers[1].sboxes)
            ....:         if j in sbox.positions})
            [0, 1, 2, 3]
        """
        maps = [linear for linear, _ in _layer_maps(self._cipher, self._layers, [self._state_index])]
        return tuple(_between_layers(self.state_input, self._layers, maps))
