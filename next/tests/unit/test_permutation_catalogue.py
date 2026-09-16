import importlib
import json
from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_every_m10_9d7_source_has_its_typed_public_class():
    inventory = json.loads((ROOT / "migration/legacy_inventory.json").read_text(encoding="utf-8"))
    records = [
        record for record in inventory["records"]
        if record.get("milestone_owner") == "M10.9d7" and record["kind"] == "source"
    ]
    assert len(records) == 25
    for record in records:
        module = importlib.import_module(record["primitive"]["proposed_module"])
        assert hasattr(module, record["primitive"]["proposed_class"])


def test_generated_permutation_parameter_indexes_are_deterministic():
    indexes = sorted(
        (ROOT / "src/claasp_next/primitives/permutations").glob("*/data/index.json")
    )
    assert len(indexes) == 22
    for path in indexes:
        variants = json.loads(path.read_text(encoding="utf-8"))["variants"]
        assert variants
        assert all(json.dumps(json.loads(key), sort_keys=True, separators=(",", ":")) == key
                   for key in variants)
