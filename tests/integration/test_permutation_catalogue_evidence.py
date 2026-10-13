import importlib
import json
from pathlib import Path

import pytest

from claasp.representations.execution import BatchEvaluator

FIXED_VECTORS = json.loads(
    (
        Path(__file__).parents[2] / "tests/fixtures/catalogue/permutation_fixed_vectors.json"
    ).read_text(encoding="utf-8")
)
PARITY_VECTORS = tuple({record["class"]: record for record in FIXED_VECTORS}.values())


def _primitive(record):
    module = importlib.import_module(record["module"])
    return getattr(module, record["class"])(**record["parameters"])


@pytest.mark.parametrize("record", FIXED_VECTORS, ids=lambda item: item["legacy_id"])
def test_every_captured_permutation_fixed_vector(record):
    primitive = _primitive(record)
    assert record["claim"] in {"legacy-fixed-vector", "specification-fixed-vector"}
    if record["claim"] == "specification-fixed-vector":
        assert record["provenance"]
    for vector in record["vectors"]:
        assert primitive.evaluate(*vector["inputs"]) == vector["output"]


@pytest.mark.parametrize("record", PARITY_VECTORS, ids=lambda item: item["class"])
def test_every_permutation_family_has_scalar_batch_parity(record):
    primitive = _primitive(record)
    vector = record["vectors"][0]
    assert primitive.evaluate(*vector["inputs"]) == vector["output"]
    decoded = {
        name: (primitive._decode_boundary(value, unit_array.array_type),)
        for (name, unit_array), value in zip(primitive.graph.input_arrays.items(), vector["inputs"])
    }
    output = BatchEvaluator().evaluate(primitive, decoded).outputs[0]
    assert primitive._encode_boundary(output, primitive.graph.output.array_type) == vector["output"]
