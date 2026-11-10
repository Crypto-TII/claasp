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


BOUNDARY_CASES = json.loads(
    Path("tests/fixtures/analysis/published_round_boundary_compatibility.json").read_text()
)


def _boundary_primitive(case):
    from claasp import primitives

    primitive = getattr(primitives, case["name"])(**case["options"])
    inputs = {
        name: tuple(value) if isinstance(value, list) else value
        for name, value in case["inputs"].items()
    }
    return primitive, inputs


@pytest.mark.parametrize("case", BOUNDARY_CASES, ids=lambda case: case["name"])
def test_new_publications_preserve_component_ids_and_outputs(case):
    from hashlib import sha256

    primitive, inputs = _boundary_primitive(case)
    expected = case["output"]
    if isinstance(expected, list):
        expected = tuple(expected)
    assert primitive.evaluate(inputs) == expected
    ids = "\n".join(component.component_id for component in primitive.graph.components)
    assert sha256(ids.encode()).hexdigest() == case["component_ids_sha256"]
    indices = tuple(index for index, _ in primitive.graph.round_output_boundaries)
    assert indices == tuple(case["published_indices"])


@pytest.mark.parametrize("case", BOUNDARY_CASES, ids=lambda case: case["name"])
@pytest.mark.parametrize("value", (0, 1, 3))
def test_new_round_cuts_recompose_the_original_primitive(case, value):
    from claasp.transformations import slice_rounds

    primitive, original = _boundary_primitive(case)
    inputs = {
        name: tuple(value for _ in old) if isinstance(old, tuple) else value
        for name, old in original.items()
    }
    expected = primitive.evaluate(inputs)
    last = len(primitive.graph.rounds) - 1
    for index, _ in primitive.graph.round_output_boundaries:
        if index == last:
            continue
        prefix = slice_rounds(primitive, 0, index).primitive
        suffix = slice_rounds(primitive, index + 1, last).primitive
        state = prefix.evaluate({name: inputs[name] for name in prefix.graph.input_arrays})
        actual = suffix.evaluate(
            {name: state if name == "state" else inputs[name] for name in suffix.graph.input_arrays}
        )
        assert actual == expected, (case["name"], index)
