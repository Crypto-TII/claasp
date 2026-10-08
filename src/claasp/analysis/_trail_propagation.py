"""Build complete component propagation for user-facing trail results."""

from functools import reduce

from claasp.components import (
    Add,
    BitVectorSBox,
    Constant,
    Identity,
    ModularAdd,
    Permutation,
    Rotate,
    Xor,
)
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    Trail,
    TrailComponentTransition,
    XorDifference,
)


def _decode(value: int, value_type) -> tuple[int, ...]:
    width = value_type.domain.encoded_bit_size
    if width is None:
        raise TypeError("trail display requires canonically encoded domains")
    mask = (1 << width) - 1
    return tuple(
        (value >> (width * (value_type.unit_count - 1 - position))) & mask
        for position in range(value_type.unit_count)
    )


def _pack(values: tuple[int, ...], width: int) -> int:
    result = 0
    for value in values:
        result = (result << width) | value
    return result


def _packed_operands(component, operands) -> XorDifference | None:
    if not operands:
        return None
    values = []
    total_width = 0
    for selection, operand in zip(component.inputs, operands):
        width = selection.value_type.domain.encoded_bit_size
        if width is None:
            raise TypeError("trail display requires canonically encoded domains")
        values.extend(operand)
        total_width += len(operand) * width
    # Components require homogeneous input domains, so packing every operand
    # with the first domain width preserves their declared input order.
    width = component.inputs[0].value_type.domain.encoded_bit_size
    return XorDifference(_pack(tuple(values), width), total_width)


def _component_name(component) -> str:
    if isinstance(component, Rotate):
        return f"rotate {component.direction} {component.amount}"
    if isinstance(component, ModularAdd):
        return "modular addition"
    if isinstance(component, (Add, Xor)):
        return "XOR"
    if isinstance(component, BitVectorSBox):
        return "S-box"
    if isinstance(component, Permutation):
        return "permutation"
    if isinstance(component, Constant):
        return "constant"
    if isinstance(component, Identity):
        return "identity"
    return type(component).__name__


def xor_differential_component_transitions(
    primitive,
    trail: Trail,
    *,
    input_differences: dict[str, int],
) -> tuple[TrailComponentTransition, ...]:
    """Propagate one checked XOR-differential witness through every component.

    Components depending only on the key are omitted for a zero-key-difference
    search. A nonzero key difference retains the key schedule as part of the
    reported propagation.
    """

    expected_inputs = set(primitive.graph.input_ports)
    if set(input_differences) != expected_inputs:
        raise ValueError("input_differences must define every primitive input")
    values = {
        name: _decode(input_differences[name], port.value_type)
        for name, port in primitive.graph.input_ports.items()
    }
    dependencies = {name: frozenset((name,)) for name in primitive.graph.input_ports}
    weighted = {step.component_id: step.transition for step in trail.steps}
    round_numbers = {
        component.component_id: primitive_round.number
        for primitive_round in primitive.graph.rounds
        for component in primitive_round.components
    }
    include_key_schedule = input_differences.get("key", 0) != 0
    result = []

    for component in primitive.graph.components:
        operands = tuple(
            tuple(primitive.graph.resolve_selection(selection, values))
            for selection in component.inputs
        )
        source_ids = {
            owner_id
            for selection in component.inputs
            for owner_id, _ in primitive.graph.selection_bit_sources(selection)
        }
        component_dependencies = frozenset(
            name for source_id in source_ids for name in dependencies[source_id]
        )
        local_transition = weighted.get(component.component_id)

        if isinstance(component, Rotate):
            width = component.output_type.domain.encoded_bit_size
            if width is None:
                raise TypeError("rotate trail display requires a canonically encoded domain")
            amount = component.amount % width
            output = tuple(
                (
                    ((value >> amount) | (value << (width - amount)))
                    if component.direction == "right"
                    else ((value << amount) | (value >> (width - amount)))
                )
                & ((1 << width) - 1)
                for value in operands[0]
            )
        elif isinstance(component, (Add, Xor)):
            output = tuple(reduce(int.__xor__, items, 0) for items in zip(*operands))
        elif isinstance(component, Permutation):
            output = tuple(operands[0][position] for position in component.mapping)
        elif isinstance(component, Constant):
            output = (0,) * component.output_type.unit_count
        elif isinstance(component, Identity):
            output = operands[0]
        elif isinstance(component, ModularAdd):
            if local_transition is not None:
                output = (local_transition.output_pattern.value,)
            elif all(value == 0 for operand in operands for value in operand):
                output = (0,) * component.output_type.unit_count
            else:
                raise ValueError(
                    f"trail has no modular-addition transition for {component.component_id}"
                )
        elif isinstance(component, BitVectorSBox):
            source = _pack(operands[0], 1)
            if local_transition is None:
                if source != 0:
                    raise ValueError(f"trail has no S-box transition for {component.component_id}")
                local_transition = SBoxTransitionSemantics(
                    component.table, output_width=component.output_bit_size
                ).xor_differential(0, 0)
            target = local_transition.output_pattern.value
            output = tuple(
                (target >> position) & 1
                for position in range(component.output_type.unit_count - 1, -1, -1)
            )
        else:
            raise NotImplementedError(
                f"full differential trail display does not support {type(component).__name__}"
            )

        values[component.component_id] = output
        dependencies[component.component_id] = component_dependencies
        is_key_schedule_only = not component_dependencies or component_dependencies <= {"key"}
        if is_key_schedule_only and not include_key_schedule:
            continue

        output_width = component.output_type.domain.encoded_bit_size
        if output_width is None:
            raise TypeError("trail display requires canonically encoded domains")
        result.append(
            TrailComponentTransition(
                round_numbers[component.component_id],
                component.component_id,
                _component_name(component),
                _packed_operands(component, operands),
                XorDifference(_pack(output, output_width), len(output) * output_width),
                local_transition,
            )
        )

    if primitive.graph.output is None:
        raise ValueError("trail primitive must declare an output")
    output = tuple(primitive.graph.resolve_selection(primitive.graph.output, values))
    output_width = primitive.graph.output.value_type.domain.encoded_bit_size
    if output_width is None:
        raise TypeError("trail display requires a canonically encoded output domain")
    if (
        _pack(output, output_width) != trail.output_pattern.value
        or len(output) * output_width != trail.output_pattern.width
    ):
        raise ValueError("component propagation does not reach the trail output pattern")
    return tuple(result)
