"""Construction coverage retained from the intermediate parity indexes."""

import importlib
import json
from pathlib import Path

import pytest

from claasp.graph import Primitive, PrimitiveKind

PARAMETER_SETS = json.loads(
    (Path(__file__).parents[2] / "migration/m10_9d_parameter_sets.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    "record",
    PARAMETER_SETS,
    ids=lambda item: f"{item['class']}:{json.dumps(item['parameters'], sort_keys=True)}",
)
@pytest.mark.extended
def test_every_audited_parameter_set_builds_from_native_source(record):
    module = importlib.import_module(record["module"])
    parameters = dict(record["parameters"])
    if record["class"] == "Subterranean" and isinstance(parameters.get("version"), str):
        parameters["version"] = module.Version[parameters["version"]]
    primitive = getattr(module, record["class"])(**parameters)
    assert isinstance(primitive, Primitive)
    assert isinstance(primitive.kind, PrimitiveKind)
    assert set(primitive.graph.input_descriptors) == set(primitive.graph.input_ports)
    assert primitive.graph.rounds
    assert primitive.graph.output is not None
