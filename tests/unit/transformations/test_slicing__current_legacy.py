"""Round extraction is checked against independently recorded legacy states."""

import enum
import importlib
import inspect
import json
from pathlib import Path

import pytest

CASES = json.loads(Path("tests/fixtures/legacy_parity/round_traces.json").read_text())["cases"]


@pytest.mark.parametrize(
    "case", [case for case in CASES if case["class"] != "RC5"], ids=lambda case: case["class"]
)
def test_first_observable_round_slice_matches_current_legacy(case):
    cls = getattr(importlib.import_module(case["module"]), case["class"])
    options = dict(case["parameters"])
    for name, parameter in inspect.signature(cls).parameters.items():
        if isinstance(parameter.default, enum.Enum) and name in options:
            options[name] = type(parameter.default)[options[name]]
    primitive = cls(**options)
    _, selections = primitive.graph.round_output_boundaries[0]
    derived = primitive.edit.slice(selections).primitive
    inputs = dict(zip(primitive.graph.input_arrays, case["inputs"]))
    expected = case["observations"]["round_output"][1 if case["class"] == "ChaskeyPi" else 0]
    assert derived.evaluate(**inputs) == expected
