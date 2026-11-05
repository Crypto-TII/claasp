"""High-precision graph propagation reusing the continuous component rules."""

from claasp.graph import GraphPropagation
from claasp.representations.execution.continuous import ContinuousExecutionDriver


def _continuous_outputs(primitive, inputs, outputs, *, carry_order="lsb_first"):
    values = {}
    for name, array in primitive.graph.input_arrays.items():
        width = array.array_type.unit_type.encoded_bit_size
        values[name] = tuple(
            tuple(inputs[name][start : start + width])
            for start in range(0, len(inputs[name]), width)
        )
    driver = ContinuousExecutionDriver(carry_order=carry_order)
    propagated = GraphPropagation(primitive).run(
        values, lambda component, operands: driver._component(primitive, component, operands)
    )
    values, cache = propagated.values, propagated.bindings
    return tuple(
        tuple(
            bit
            for selection in selections
            for unit in primitive.graph.resolve_selection(selection, values, cache)
            for bit in unit
        )
        for selections in outputs
    )
