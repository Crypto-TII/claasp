import importlib
import json
from pathlib import Path

import pytest

from claasp_next.representations.execution import BatchEvaluator


VECTORS = json.loads(
    (Path(__file__).parents[2] / "migration" / "m10_9d6_zero_regressions.json").read_text(
        encoding="utf-8"
    )
)
FIXED_VECTORS = json.loads(
    (Path(__file__).parents[2] / "migration" / "m10_9d6_fixed_vectors.json").read_text(
        encoding="utf-8"
    )
)


def _primitive(record):
    module = importlib.import_module(record["module"])
    parameters = dict(record.get("parameters", {}))
    if record["class"] == "Subterranean" and isinstance(parameters.get("version"), str):
        parameters["version"] = module.Version[parameters["version"]]
    return getattr(module, record["class"])(**parameters)


@pytest.mark.parametrize("vector", VECTORS, ids=lambda item: item["class"])
def test_every_m10_9d6_default_graph_preserves_legacy_zero_regression(vector):
    primitive = _primitive(vector)
    assert primitive.evaluate(*vector["inputs"]) == vector["output"]
    decoded = {
        name: (primitive._decode_boundary(value, port.value_type),)
        for (name, port), value in zip(primitive.input_ports.items(), vector["inputs"])
    }
    batch_output = BatchEvaluator().evaluate(primitive, decoded).outputs[0]
    assert primitive._encode_boundary(batch_output, primitive.output.value_type) == vector["output"]
    assert vector["claim"] == "legacy-regression"


@pytest.mark.parametrize(
    "record", FIXED_VECTORS,
    ids=lambda item: item["legacy_id"],
)
def test_every_captured_legacy_fixed_vector(record):
    primitive = _primitive(record)
    assert record["claim"] == "legacy-fixed-vector"
    for vector in record["vectors"]:
        assert primitive.evaluate(*vector["inputs"]) == vector["output"]
