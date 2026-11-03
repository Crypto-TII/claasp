"""Published boundaries agree with independently executed legacy traces."""

import enum
import importlib
import inspect
import json
from pathlib import Path

import pytest

DATA = json.loads(Path("tests/fixtures/legacy_parity/round_traces.json").read_text())


@pytest.mark.parametrize("case", DATA["cases"], ids=lambda case: case["class"])
def test_round_states_match_current_legacy(case):
    cls = getattr(importlib.import_module(case["module"]), case["class"])
    options = dict(case["parameters"])
    signature = inspect.signature(cls)
    for name, value in options.items():
        default = signature.parameters[name].default
        if isinstance(default, enum.Enum) and isinstance(value, str):
            options[name] = type(default)[value]
    primitive = cls(**options)
    trace = primitive.evaluate_with_trace(*case["inputs"])
    states = []
    for _, selections in primitive.graph.round_output_boundaries:
        value = 0
        for selection in selections:
            width = selection.array_type.unit_type.encoded_bit_size
            assert width is not None
            for unit in primitive.graph.resolve_selection(selection, trace.values, {}):
                value = (value << width) | unit
        states.append(value)
    expected = case["observations"].get("round_output", []) + case["observations"].get(
        "cipher_output", []
    )
    # These legacy constructors publish the final state under both tags.
    if case["class"] in {"Present", "Simon", "TEA", "XTEA"}:
        assert expected[-2] == expected[-1]
        expected = expected[:-1]
    # Legacy Chaskey publishes balanced half rounds; v5 reports full rounds.
    if case["class"] == "ChaskeyPi":
        expected = expected[1::2]
    # Legacy RC5 publishes no intermediate states. Its sole observable final
    # state still agrees; v5 additionally publishes the intervening ARX states.
    if case["class"] == "RC5":
        assert len(states) == case["parameters"]["number_of_rounds"]
        states = states[-1:]
    assert states == expected
    assert primitive.evaluate(*case["inputs"]) == case["output"]
