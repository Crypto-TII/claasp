"""Round-key removal must classify selected units rather than an entire join."""

import pytest

from claasp.primitives import LEA, Speck, Ublock
from claasp.transformations import remove_key_schedule


@pytest.mark.parametrize(
    "primitive", [Ublock(number_of_rounds=2), LEA(number_of_rounds=2), Speck(number_of_rounds=2)]
)
def test_exposed_key_slices_reproduce_original_evaluations(primitive):
    transformed = remove_key_schedule(primitive)
    for value in (0, 3, 0x1234):
        original_inputs = {name: value for name in primitive.graph.input_arrays}
        inputs = transformed.bind_inputs(**original_inputs)
        assert "key" not in transformed.primitive.graph.input_arrays
        assert all(
            source in primitive.graph.input_arrays or primitive.graph.unit_array(source)
            for source, _ in transformed.sources
        )
        assert transformed.primitive.evaluate(**inputs) == primitive.evaluate(**original_inputs)


@pytest.mark.parametrize("primitive", [Ublock(number_of_rounds=2), LEA(number_of_rounds=2)])
def test_keyless_joined_graph_matches_explicit_zero_round_keys(primitive):
    retained = remove_key_schedule(primitive).primitive
    removed = remove_key_schedule(primitive, keep_round_key_injection=False)
    inputs = {name: 0 for name in retained.graph.input_arrays}
    inputs["plaintext"] = 0x1234
    assert tuple(removed.primitive.graph.input_arrays) == ("plaintext",)
    assert removed.primitive.evaluate(0x1234) == retained.evaluate(**inputs)
