"""Derive the optimized circle SPN representation from the typed graph.

This is an affine propagation rule, run by the common graph interpreter. It
derives primitive structure, constants and key schedules from graph operations.
"""

from dataclasses import dataclass
from functools import reduce

from claasp.components import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    Constant,
    Identity,
    LinearMap,
    Permutation,
    Rotate,
    SBox,
    Shift,
    Xor,
)
from claasp.graph import GraphPropagation
from claasp.semantics.cryptanalysis.bibrace import CircleBasis
from claasp.semantics.cryptanalysis.circle_linear import CircleAffineLayer
from claasp.unit_types import BinaryExtensionField, Bit, Word


@dataclass(frozen=True)
class _AffineBit:
    expression: int
    generation: int | None = None

    def __xor__(self, other):
        if (
            self.generation is not None
            and other.generation is not None
            and self.generation != other.generation
        ):
            raise ValueError("circle subgroup extraction cannot mix different round states")
        return _AffineBit(
            self.expression ^ other.expression,
            self.generation if self.generation is not None else other.generation,
        )


def _flat(units):
    return tuple(
        bit for unit in units for bit in ((unit,) if isinstance(unit, _AffineBit) else unit)
    )


def _units(bits, array_type):
    if isinstance(array_type.unit_type, Bit):
        return tuple(bits)
    width = array_type.unit_type.encoded_bit_size
    return tuple(tuple(bits[i : i + width]) for i in range(0, len(bits), width))


def subgroup_model_from_graph(primitive, bibrace, *, input_name="plaintext", fixed_inputs=None):
    """Extract a homogeneous, binary cell-XOR SPN or reject its capability.

    Fixed public inputs are substituted, secret inputs remain symbolic in a
    shared master-key coordinate system. Each round must publish one complete
    parallel substitution layer. Key schedules must be affine. Cell diffusion
    and the cell permutation must be identical across the selected rounds.
    """
    from claasp.analysis.circle_linear_spn import FreeSubgroupSPN

    plan = GraphPropagation(primitive)
    graph = primitive.graph
    if input_name not in graph.input_arrays or input_name in graph.secret_inputs:
        raise ValueError("circle subgroup input must name a public primitive input")
    n = graph.input_arrays[input_name].array_type.encoded_bit_size
    if n is None or n % bibrace.width or graph.output is None:
        raise ValueError("circle subgroup boundaries must have a tiled binary encoding")
    if graph.output.array_type.encoded_bit_size != n:
        raise ValueError("circle subgroup extraction requires equal input/output widths")
    for _, array_type in plan.sources:
        if not isinstance(array_type.unit_type, (Bit, Word, BinaryExtensionField)):
            raise NotImplementedError("circle subgroup extraction requires binary unit types")
    cells, w = n // bibrace.width, bibrace.width
    secret_names = tuple(name for name in graph.input_arrays if name in graph.secret_inputs)
    key_width = sum(graph.input_arrays[name].array_type.encoded_bit_size for name in secret_names)
    fixed = dict(fixed_inputs or {})
    expected = set(graph.input_arrays) - set(secret_names) - {input_name}
    if set(fixed) != expected:
        raise ValueError(f"fixed_inputs must contain exactly {sorted(expected)}")
    constant_bit = 1 << (n + key_width)
    state_mask, key_mask = (1 << n) - 1, (1 << key_width) - 1
    values = {}
    key_remaining = key_width
    for name, array in graph.input_arrays.items():
        width = array.array_type.encoded_bit_size
        if name == input_name:
            bits = tuple(_AffineBit(1 << bit, -1) for bit in reversed(range(n)))
        elif name in secret_names:
            key_remaining -= width
            bits = tuple(
                _AffineBit(1 << (n + key_remaining + bit)) for bit in reversed(range(width))
            )
        else:
            decoded = primitive._decode_boundary(fixed[name], array.array_type)
            packed = primitive._encode_boundary(decoded, array.array_type)
            assert isinstance(packed, int)
            bits = tuple(
                _AffineBit(constant_bit if packed >> bit & 1 else 0)
                for bit in reversed(range(width))
            )
        values[name] = _units(bits, array.array_type)

    boundaries = dict(graph.round_output_boundaries)
    round_indices = {r.number: i for i, r in enumerate(graph.rounds)}
    before: list[list[_AffineBit | None]] = [[None] * n for _ in graph.rounds]
    boundary_sources = []
    positions = []
    for r in graph.rounds:
        selections = boundaries.get(r.number)
        if selections is None:
            raise ValueError("circle subgroup extraction requires published round boundaries")
        refs = tuple(ref for item in selections for ref in plan.bit_sources(item))
        if len(refs) != n or len(set(refs)) != n:
            raise ValueError("circle subgroup round boundary must contain each state bit once")
        boundary_sources.append(refs)
        positions.append({ref: i for i, ref in enumerate(refs)})
    tables = []
    permutations: list[list[tuple[int, ...]]] = [[] for _ in graph.rounds]

    def rule(component, operands):
        ri = round_indices[plan.round_numbers[component.component_id]]
        zero = _AffineBit(0)
        if isinstance(component, Constant):
            width = component.output_type.unit_type.encoded_bit_size
            assert width is not None
            return _units(
                tuple(
                    _AffineBit(constant_bit if value >> bit & 1 else 0)
                    for value in component.values
                    for bit in reversed(range(width))
                ),
                component.output_type,
            )
        if isinstance(component, Identity):
            return operands[0]
        if isinstance(component, Permutation):
            if (
                len(component.mapping) == cells
                and component.output_type.unit_type.encoded_bit_size == w
            ):
                permutations[ri].append(tuple(component.mapping))
            return tuple(operands[0][i] for i in component.mapping)
        if isinstance(component, (Xor, Add)):
            if isinstance(component, Add) and not isinstance(
                component.output_type.unit_type, (Bit, BinaryExtensionField)
            ):
                raise NotImplementedError("circle affine extraction requires binary addition")
            flat = tuple(_flat(operand) for operand in operands)
            return _units(
                tuple(reduce(_AffineBit.__xor__, column, zero) for column in zip(*flat)),
                component.output_type,
            )
        if isinstance(component, (Rotate, Shift)):
            width = component.output_type.unit_type.encoded_bit_size
            assert width is not None
            result: list[_AffineBit] = []
            for unit in operands[0]:
                bits = list((unit,) if isinstance(unit, _AffineBit) else unit)
                if isinstance(component, Rotate):
                    amount = component.amount % width
                    if component.direction == "right":
                        amount = -amount
                    bits = bits[amount:] + bits[:amount]
                else:
                    amount = min(component.amount, width)
                    bits = (
                        bits[amount:] + [zero] * amount
                        if component.direction == "left"
                        else [zero] * amount + bits[: width - amount]
                    )
                result.extend(bits)
            return _units(tuple(result), component.output_type)
        if isinstance(component, (LinearMap, BinaryAffineMap)):
            from claasp.analysis.linear_properties import expand_binary_field_matrix

            matrix = component.matrix
            if isinstance(component, LinearMap) and isinstance(
                component.output_type.unit_type, BinaryExtensionField
            ):
                matrix = expand_binary_field_matrix(matrix, component.output_type.unit_type)
            source = _flat(operands[0])
            width = len(matrix[0])
            groups = tuple(source[i : i + width] for i in range(0, len(source), width))
            result = []
            for group in groups:
                for i, row in enumerate(matrix):
                    value = reduce(
                        _AffineBit.__xor__,
                        (bit for bit, coefficient in zip(group, row) if coefficient),
                        zero,
                    )
                    if (
                        isinstance(component, BinaryAffineMap)
                        and component.offset >> (len(matrix) - 1 - i) & 1
                    ):
                        value ^= _AffineBit(constant_bit)
                    result.append(value)
            return _units(tuple(result), component.output_type)
        if isinstance(component, (SBox, BitVectorSBox)):
            if len(component.table) != 1 << w or len(_flat(operands[0])) % w:
                raise ValueError("circle subgroup S-box width must match the bibrace")
            tables.append(tuple(component.table))
            output = []
            for bit, expression in enumerate(_flat(operands[0])):
                ref = (component.component_id, bit)
                if ref not in positions[ri]:
                    raise ValueError("circle subgroup round must end at its parallel S-box layer")
                position = positions[ri][ref]
                if expression.generation not in (None, ri - 1):
                    raise ValueError("circle subgroup requires one nonlinear layer per round")
                before[ri][position] = expression
                output.append(_AffineBit(1 << (n - 1 - position), ri))
            return _units(tuple(output), component.output_type)
        raise NotImplementedError(
            f"circle subgroup affine extraction has no rule for {type(component).__name__}"
        )

    propagated = plan.run(values, rule)
    output_refs = plan.bit_sources(graph.output)
    if output_refs != boundary_sources[-1]:
        raise ValueError("circle subgroup output must equal the last round boundary")
    if not tables or any(table != tables[0] for table in tables):
        raise ValueError("circle subgroup requires the same S-box at every state cell")
    layers, diffusions, chosen_permutations = [], [], []
    basis = CircleBasis((bibrace,) * cells)
    for ri, retained in enumerate(before):
        if any(expression is None for expression in retained):
            raise ValueError("circle subgroup round must publish a complete parallel S-box layer")
        expressions = [expression for expression in retained if expression is not None]
        permutation = permutations[ri][-1] if permutations[ri] else tuple(range(cells))
        inverse = tuple(permutation.index(i) for i in range(cells))
        expressions = [expressions[inverse[i] * w + b] for i in range(cells) for b in range(w)]
        rows = tuple(expression.expression & state_mask for expression in reversed(expressions))
        key_rows = tuple(
            (expression.expression >> n) & key_mask for expression in reversed(expressions)
        )
        offset = sum(
            int(bool(expression.expression & constant_bit)) << bit
            for bit, expression in enumerate(reversed(expressions))
        )
        diffusion = []
        for i in range(cells):
            support = sum(
                1 << j
                for j in range(cells)
                if rows[w * (cells - 1 - i)] >> (w * (cells - 1 - j)) & 1
            )
            for b in range(w):
                expected_row = sum(
                    1 << (w * (cells - 1 - j) + b) for j in range(cells) if support >> j & 1
                )
                if rows[w * (cells - 1 - i) + b] != expected_row:
                    raise ValueError(
                        "circle subgroup diffusion must XOR whole cells without mixing cell bits"
                    )
            diffusion.append(support)
        diffusions.append(tuple(diffusion))
        chosen_permutations.append(permutation)
        layers.append(CircleAffineLayer(basis, basis, rows, offset, key_width, key_rows))
    if len(set(diffusions)) != 1 or len(set(chosen_permutations)) != 1:
        raise ValueError("circle subgroup requires homogeneous diffusion and cell permutation")
    # Accessing propagated output ensures the complete graph, including all
    # structural conversions and key-schedule components, has been interpreted.
    assert propagated.output is not None
    return FreeSubgroupSPN(
        bibrace,
        tables[0],
        diffusions[0],
        chosen_permutations[0],
        len(graph.rounds),
        affine_layers=tuple(layers),
    )
