import importlib
import json
from pathlib import Path

import pytest

from claasp_next.representations.execution import BatchEvaluator


FIXED_VECTORS = json.loads(
    (Path(__file__).parents[2] / "migration" / "m10_9d7_fixed_vectors.json").read_text(
        encoding="utf-8"
    )
)
PARITY_VECTORS = tuple({record["class"]: record for record in FIXED_VECTORS}.values())


def _primitive(record):
    module = importlib.import_module(record["module"])
    return getattr(module, record["class"])(**record["parameters"])


@pytest.mark.parametrize("record", FIXED_VECTORS, ids=lambda item: item["legacy_id"])
def test_every_captured_permutation_fixed_vector(record):
    primitive = _primitive(record)
    assert record["claim"] == "legacy-fixed-vector"
    for vector in record["vectors"]:
        assert primitive.evaluate(*vector["inputs"]) == vector["output"]


@pytest.mark.parametrize("record", PARITY_VECTORS, ids=lambda item: item["class"])
def test_every_permutation_family_has_scalar_batch_parity(record):
    primitive = _primitive(record)
    vector = record["vectors"][0]
    assert primitive.evaluate(*vector["inputs"]) == vector["output"]
    decoded = {
        name: (primitive._decode_boundary(value, port.value_type),)
        for (name, port), value in zip(primitive.input_ports.items(), vector["inputs"])
    }
    output = BatchEvaluator().evaluate(primitive, decoded).outputs[0]
    assert primitive._encode_boundary(output, primitive.output.value_type) == vector["output"]
