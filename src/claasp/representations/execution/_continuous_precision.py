"""High-precision graph propagation reusing the continuous component rules."""

from claasp.representations.execution.continuous import ContinuousExecutionDriver


def _continuous_outputs(primitive, inputs, outputs):
    values = {}
    for name, array in primitive.graph.input_arrays.items():
        width = array.array_type.unit_type.encoded_bit_size
        values[name] = tuple(
            tuple(inputs[name][start : start + width])
            for start in range(0, len(inputs[name]), width)
        )
    cache: dict[str, tuple] = {}
    driver = ContinuousExecutionDriver()
    for component in primitive.graph.components:
        selected = tuple(
            primitive.graph.resolve_selection(item, values, cache) for item in component.inputs
        )
        values[component.component_id] = driver._component(primitive, component, selected)
    return tuple(
        tuple(
            bit
            for selection in selections
            for unit in primitive.graph.resolve_selection(selection, values, cache)
            for bit in unit
        )
        for selections in outputs
    )
