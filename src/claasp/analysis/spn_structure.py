"""Structural substitution/permutation decomposition of typed binary graphs.

Chi recognition follows develop PR #726. Linear maps are composed over GF(2),
without evaluating the primitive or probing key-dependent round functions.
"""

from dataclasses import dataclass
from functools import cached_property, reduce
from operator import xor

from claasp.components import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    Constant,
    Identity,
    LinearMap,
    Permutation,
    Rotate,
    SBox,
    Shift,
    Xor,
)
from claasp.graph.primitive import PrimitiveGraph
from claasp.unit_types import BinaryExtensionField, Bit, Word

_MAX_CHI_SBOX_SIZE = 16


@dataclass(frozen=True)
class SubstitutionBox:
    """One immutable lookup table and its MSB-first graph/state positions.

    EXAMPLES::

        >>> box = SubstitutionBox((0,), (0, 1), (('x', 0),), (('y', 0),))
        >>> box.table
        (0, 1)
    """

    positions: tuple[int, ...]
    table: tuple[int, ...]
    input_bits: tuple[tuple[str, int], ...]
    output_bits: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class SubstitutionLayer:
    """A full-state layer of parallel explicit S-boxes or chi rows.

    EXAMPLES::

        >>> layer = SubstitutionLayer(0, 'sbox', (('x', 0),), (('y', 0),), ())
        >>> layer.round_number, len(layer.input_bits)
        (0, 1)
    """

    round_number: int
    kind: str
    input_bits: tuple[tuple[str, int], ...]
    output_bits: tuple[tuple[str, int], ...]
    sboxes: tuple[SubstitutionBox, ...]


def _sbox(positions, table, inputs, outputs):
    return SubstitutionBox(tuple(positions), tuple(table), tuple(inputs), tuple(outputs))


def _operands(graph, component):
    return [graph.selection_bit_sources(selection) for selection in component.inputs]


def _operation(component):
    return {Xor: "XOR", BitwiseAnd: "AND", BitwiseNot: "NOT"}.get(type(component))


def _split_chi_xor(graph, component, ands):
    """``(linear operand, AND operands)`` of a chi XOR, ``None`` for an XOR not fed by any AND."""
    operands = _operands(graph, component)
    from_and = [all(link in ands for link, _ in operand) for operand in operands]
    if not any(from_and):
        return None
    linear = [operand for operand, is_and in zip(operands, from_and) if not is_and]
    if len(linear) != 1 or any(link in ands for link, _ in linear[0]):
        raise ValueError(
            f"{component.component_id}: expected one linear operand XOR AND terms (chi-like layer)"
        )
    return linear[0], [operand for operand, is_and in zip(operands, from_and) if is_and]


def _literal(graph, bit, nots, index, round_number):
    """``(source index, flip)`` of an AND input bit, ``flip = 1`` when it goes through a NOT."""
    link, position = bit
    flip = 0
    if link in nots:
        link, position = _operands(graph, nots[link])[0][position]
        flip = 1
    if (link, position) not in index:
        raise ValueError(
            f"round {round_number}: AND input {bit} is not a bit entering the chi layer"
        )
    return index[(link, position)], flip


def _chi_sbox_table(positions, formulas):
    """Table of the chi output bits ``positions``: bit `i` is `x_i` plus the AND terms of ``formulas[i]``."""
    m = len(positions)
    local = {i: k for k, i in enumerate(positions)}
    table = []
    for word in range(2**m):
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
    adjacency: list[set[int]] = [set() for _ in formulas]
    for i, formula in enumerate(formulas):
        for term in formula:
            for j, _ in term:
                adjacency[i].add(j)
                adjacency[j].add(i)
    remaining = set(range(len(formulas)))
    groups = []
    while remaining:
        pending, seen = [min(remaining)], set()
        while pending:
            vertex = pending.pop()
            if vertex not in seen:
                seen.add(vertex)
                pending.extend(adjacency[vertex] - seen)
        remaining -= seen
        positions = sorted(seen)
        if len(positions) > _MAX_CHI_SBOX_SIZE:
            raise ValueError(
                f"round {round_number}: a chi row of {len(positions)} bits "
                f"(at most {_MAX_CHI_SBOX_SIZE} supported)"
            )
        groups.append(
            _sbox(
                positions,
                _chi_sbox_table(positions, formulas),
                [sources[p] for p in positions],
                [outputs[p] for p in positions],
            )
        )
    return tuple(groups)


def _chi_layer(graph, round_number, components):
    by_id = {c.component_id: c for c in components}
    ands = {c.component_id for c in components if _operation(c) == "AND"}
    nots = {c.component_id: c for c in components if _operation(c) == "NOT"}
    # sources: linear operands of the chi XORs; outputs: the XOR output bit of each; terms: its AND bits
    sources, outputs, terms, chi_xors = [], [], [], set()
    for component in components:
        split = _split_chi_xor(graph, component, ands) if _operation(component) == "XOR" else None
        if split is None:
            continue
        linear, and_operands = split
        chi_xors.add(component.component_id)
        sources += linear
        outputs += [
            (component.component_id, bit) for bit in range(component.output_type.encoded_bit_size)
        ]
        terms += [
            [operand[bit] for operand in and_operands]
            for bit in range(component.output_type.encoded_bit_size)
        ]
    if not sources:
        raise ValueError(f"round {round_number}: AND components outside a chi-like layer")
    if len(set(sources)) != len(sources):
        raise ValueError(f"round {round_number}: a bit is the linear operand of two chi outputs")
    index = {source: i for i, source in enumerate(sources)}
    # per output bit: AND terms, each a list of (source index, flip)
    formulas = [
        [
            [
                _literal(graph, operand[position], nots, index, round_number)
                for operand in _operands(graph, by_id[link])
            ]
            for link, position in bit_terms
        ]
        for bit_terms in terms
    ]
    return (
        SubstitutionLayer(
            round_number,
            "chi",
            tuple(sources),
            tuple(outputs),
            _chi_sboxes(formulas, round_number, sources, outputs),
        ),
        frozenset(link for link, _ in sources),
        frozenset(chi_xors),
    )


def _explicit_layer(graph, number, components):
    inputs: list[tuple[str, int]] = []
    outputs: list[tuple[str, int]] = []
    boxes = []
    for component in components:
        source = tuple(bit for operand in _operands(graph, component) for bit in operand)
        target = tuple(
            (component.component_id, bit) for bit in range(component.output_type.encoded_bit_size)
        )
        width = (
            len(source)
            if isinstance(component, BitVectorSBox)
            else component.inputs[0].array_type.unit_type.encoded_bit_size
        )
        output_width = (
            len(target)
            if isinstance(component, BitVectorSBox)
            else component.output_type.unit_type.encoded_bit_size
        )
        if width != output_width:
            raise ValueError("SPN substitution boxes must be square")
        for start in range(0, len(source), width):
            positions = range(len(inputs), len(inputs) + width)
            boxes.append(
                _sbox(
                    positions,
                    component.table,
                    source[start : start + width],
                    target[start : start + width],
                )
            )
            inputs.extend(source[start : start + width])
            outputs.extend(target[start : start + width])
    return SubstitutionLayer(number, "sbox", tuple(inputs), tuple(outputs), tuple(boxes))


def _bit_size(array_type):
    size = array_type.encoded_bit_size
    if size is None:
        raise ValueError("SPN extraction requires finite binary encodings")
    return size


def _data_path(graph, state):
    dependencies = {name: name == state for name in graph.input_arrays}
    selected = set()
    for component in graph.components:
        live = any(
            dependencies[name] for operand in _operands(graph, component) for name, _ in operand
        )
        dependencies[component.component_id] = live
        if live:
            selected.add(component.component_id)
    return selected


def _check_boundaries(graph, layers, state):
    components = {c.component_id: c for c in graph.components}
    prior = set()
    for index, layer in enumerate((*layers, None)):
        sources = graph.selection_bit_sources(graph.output) if layer is None else layer.input_bits
        own = set() if layer is None else set(layer.output_bits)
        pending, seen = list(sources), set()
        while pending:
            bit = pending.pop()
            if bit in own:
                raise ValueError("substitution components must be applied in parallel")
            if bit in prior or bit in seen:
                continue
            seen.add(bit)
            name, _ = bit
            if index and name == state:
                raise ValueError("state path bypasses a substitution layer")
            if name in components:
                pending.extend(
                    item for operand in _operands(graph, components[name]) for item in operand
                )
        prior = own


def _affine(component, operands):
    """Compose integer bitsets representing GF(2) row vectors, without probes."""
    width = component.output_type.unit_type.encoded_bit_size
    size = component.output_type.encoded_bit_size
    flat = tuple(bit for operand in operands for bit in operand)
    if isinstance(component, Constant):
        return (0,) * size
    if isinstance(component, (Identity, BitwiseNot)):
        return flat
    if isinstance(component, (Xor, Add)):
        return tuple(reduce(xor, column, 0) for column in zip(*operands))
    if isinstance(component, (Rotate, Shift)):
        result = []
        for start in range(0, size, width):
            for bit in range(width):
                source = (
                    bit - component.amount
                    if component.direction == "right"
                    else bit + component.amount
                )
                if isinstance(component, Rotate):
                    source %= width
                result.append(flat[start + source] if 0 <= source < width else 0)
        return tuple(result)
    if isinstance(component, Permutation):
        return tuple(flat[unit * width + bit] for unit in component.mapping for bit in range(width))
    if isinstance(component, (LinearMap, BinaryAffineMap)):
        from claasp.analysis.linear_properties import expand_binary_field_matrix

        matrix = component.matrix
        if isinstance(component, LinearMap) and isinstance(
            component.output_type.unit_type, BinaryExtensionField
        ):
            matrix = expand_binary_field_matrix(matrix, component.output_type.unit_type)
        groups = (
            (tuple(flat[start : start + width]) for start in range(0, size, width))
            if isinstance(component, BinaryAffineMap)
            else (flat,)
        )
        return tuple(
            reduce(xor, (value for value, coefficient in zip(group, row) if coefficient), 0)
            for group in groups
            for row in matrix
        )
    raise ValueError(
        f"{component.component_id}: unsupported affine operation {type(component).__name__}"
    )


@dataclass(frozen=True, init=False)
class SpnStructure:
    """Extract complete substitution layers and their following GF(2) maps.

    Reads a snapshot of the typed graph, excluding secret-only key/tweak
    computations. Supports explicit square S-boxes and chi-like NOT/AND/XOR
    rows up to 16 bits. Rejects partial layers, nonlinear cascades in one
    round, unsupported state operations, and paths bypassing substitution.
    Affine-only prefix/suffix rounds are allowed. State positions are each
    layer's own MSB-first numbering. Matrices exclude constants and keys.

    EXAMPLES::

        >>> from claasp.primitives import AES
        >>> structure = SpnStructure(AES(number_of_rounds=2))
        >>> structure.state_input, structure.state_size, structure.key_size
        ('plaintext', 128, 128)
        >>> [len(layer.sboxes) for layer in structure.substitution_layers]
        [16, 16]
        >>> len(structure.linear_layers[-1]), sum(map(sum, structure.linear_layers[-1]))
        (128, 736)
    """

    _graph: PrimitiveGraph
    _live: set[str]
    state_input: str
    state_size: int
    key_size: int
    substitution_layers: tuple[SubstitutionLayer, ...]

    def __init__(self, primitive):
        from copy import deepcopy

        graph = deepcopy(primitive.graph)
        if graph.output is None:
            raise ValueError("SPN graph must declare an output")
        for array in graph.input_arrays.values():
            _bit_size(array.array_type)
        keys = {
            name
            for name, descriptor in graph.input_descriptors.items()
            if descriptor.is_secret or descriptor.role in ("key", "tweak")
        }
        public = set(graph.input_arrays) - keys
        if len(public) != 1:
            raise ValueError(
                "SPN extraction requires one state input besides secret key/tweak inputs"
            )
        state = next(iter(public))
        if not isinstance(
            graph.input_arrays[state].array_type.unit_type, (Bit, Word, BinaryExtensionField)
        ):
            raise ValueError("SPN state must use binary units")
        state_size = _bit_size(graph.input_arrays[state].array_type)
        live = _data_path(graph, state)
        allowed = (
            BitVectorSBox,
            SBox,
            BitwiseAnd,
            BitwiseNot,
            Xor,
            Constant,
            Identity,
            Rotate,
            Shift,
            Permutation,
            LinearMap,
            BinaryAffineMap,
        )
        layers = []
        chi_outputs = set()
        for round_ in graph.rounds:
            components = [c for c in round_.components if c.component_id in live]
            for component in components:
                if isinstance(component, LinearMap) and not isinstance(
                    component.output_type.unit_type, (Bit, BinaryExtensionField)
                ):
                    raise ValueError("SPN linear maps require a binary field")
                if not isinstance(component, allowed) and not (
                    isinstance(component, Add)
                    and isinstance(component.output_type.unit_type, (Bit, BinaryExtensionField))
                ):
                    raise ValueError(
                        f"{component.component_id}: unsupported SPN operation {type(component).__name__}"
                    )
            boxes = [c for c in components if isinstance(c, (BitVectorSBox, SBox))]
            ands = [c for c in components if isinstance(c, BitwiseAnd)]
            if boxes and ands:
                raise ValueError("a round cannot mix explicit S-boxes and chi AND operations")
            if boxes:
                layers.append(_explicit_layer(graph, round_.number, boxes))
            elif ands:
                layer, _, outputs = _chi_layer(graph, round_.number, components)
                layers.append(layer)
                chi_outputs.update(outputs)
        if not layers:
            raise ValueError("primitive has no substitution layer")
        if any(len(layer.input_bits) != state_size for layer in layers):
            raise ValueError("every substitution layer must cover the complete state")
        for layer in layers:
            if len(set(layer.output_bits)) != state_size:
                raise ValueError("a substitution layer repeats output bits")
        and_ids = {
            c.component_id
            for c in graph.components
            if c.component_id in live and isinstance(c, BitwiseAnd)
        }
        for component in graph.components:
            if component.component_id not in chi_outputs and any(
                name in and_ids for operand in _operands(graph, component) for name, _ in operand
            ):
                raise ValueError("AND output is used outside a chi substitution layer")
        _check_boundaries(graph, layers, state)
        object.__setattr__(self, "_graph", graph)
        object.__setattr__(self, "_live", live)
        object.__setattr__(self, "state_input", state)
        object.__setattr__(self, "state_size", state_size)
        object.__setattr__(
            self,
            "key_size",
            sum(graph.input_arrays[name].array_type.encoded_bit_size for name in keys),
        )
        object.__setattr__(self, "substitution_layers", tuple(layers))

    def __repr__(self):
        return (
            f"SpnStructure(state={self.state_input!r}, size={self.state_size}, "
            f"layers={len(self.substitution_layers)})"
        )

    @cached_property
    def linear_layers(self) -> tuple[tuple[tuple[int, ...], ...], ...]:
        """Return immutable row-major maps from each layer to the next or output.

        ``matrix[j][i]`` is the contribution of output bit i of the current
        substitution layer to input bit j of the next. The final map targets
        the primitive output. Key and constant offsets are omitted. These
        describe value maps, rather than differential or linear-mask trails.

        EXAMPLES::

            >>> from claasp.primitives import Present
            >>> structure = SpnStructure(Present(number_of_rounds=1))
            >>> sum(map(sum, structure.linear_layers[0]))
            64
        """
        graph = self._graph
        layers = self.substitution_layers
        positions = {bit: index for layer in layers for index, bit in enumerate(layer.output_bits)}
        output_ids = {name for name, _ in positions}
        forms = {
            name: (0,) * _bit_size(array.array_type) for name, array in graph.input_arrays.items()
        }
        for component in graph.components:
            size = _bit_size(component.output_type)
            name = component.component_id
            assert name is not None
            if name in output_ids:
                forms[name] = tuple(1 << positions[name, bit] for bit in range(size))
            elif name not in self._live or isinstance(component, BitwiseAnd):
                forms[name] = (0,) * size
            else:
                operands = tuple(
                    tuple(forms[source][bit] for source, bit in operand)
                    for operand in _operands(graph, component)
                )
                forms[name] = _affine(component, operands)
        assert graph.output is not None
        targets = [layer.input_bits for layer in layers[1:]] + [
            graph.selection_bit_sources(graph.output)
        ]
        return tuple(
            tuple(
                tuple((forms[name][bit] >> index) & 1 for index in range(self.state_size))
                for name, bit in target
            )
            for target in targets
        )
