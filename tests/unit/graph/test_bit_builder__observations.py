"""Legacy bit-graph output markers must be observable through the typed graph."""

import pytest

from claasp.primitives import DES, Serpent, Simon


@pytest.mark.parametrize(
    "primitive", [DES(number_of_rounds=3), Simon(number_of_rounds=3), Serpent(number_of_rounds=3)]
)
def test_bit_graph_publishes_every_round_and_final_output(primitive):
    boundaries = primitive.graph.round_output_boundaries
    assert len(boundaries) == 3
    inputs = {name: 0 for name in primitive.graph.input_arrays}
    execution = primitive.evaluate_with_trace(**inputs)
    last = boundaries[-1][1]
    values = tuple(
        value
        for selection in last
        for value in primitive.graph.resolve_selection(selection, execution.values)
    )
    assert primitive._encode_boundary(
        values, primitive.graph.output.array_type
    ) == primitive.evaluate(**inputs)


def test_round_keys_and_named_outputs_are_retained():
    primitive = Serpent(number_of_rounds=2)
    assert len(primitive.graph.round_keys) == 3
    assert any("round_key_output" in row for row in primitive.graph.intermediate_outputs)
