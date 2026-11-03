"""Retained state boundaries stay usable by per-round analysis after slicing."""

from claasp.primitives import Speck
from claasp.transformations import remove_key_schedule, slice_rounds


def _states(primitive, inputs):
    trace = primitive.evaluate_with_trace(**inputs)
    return tuple(
        tuple(
            unit
            for selection in selections
            for unit in primitive.graph.resolve_selection(selection, trace.values, {})
        )
        for _, selections in primitive.graph.round_output_boundaries
    )


def test_middle_round_slice_retains_only_its_original_round_observations():
    original = Speck(number_of_rounds=4)
    inputs = {"plaintext": 0x6574694C, "key": 0x1918111009080100}
    states = _states(original, inputs)
    sliced = slice_rounds(original, 1, 2).primitive
    assert _states(sliced, {"state": states[0], "key": inputs["key"]}) == states[1:3]
    assert sliced.details().number_of_rounds == 2


def test_exposed_round_keys_preserve_states_and_publish_key_inputs():
    original = Speck(number_of_rounds=3)
    inputs = {"plaintext": 0x6574694C, "key": 0x1918111009080100}
    result = remove_key_schedule(original)
    assert _states(result.primitive, result.bind_inputs(**inputs)) == _states(original, inputs)
    assert len(result.primitive.graph.round_keys) == 3
