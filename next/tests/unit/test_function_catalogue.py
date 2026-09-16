import importlib
import json
from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_every_m10_9d8_source_has_its_typed_public_class():
    inventory = json.loads((ROOT / "migration/legacy_inventory.json").read_text(encoding="utf-8"))
    records = [
        record for record in inventory["records"]
        if record.get("milestone_owner") == "M10.9d8" and record["kind"] == "source"
    ]
    assert len(records) == 15
    for record in records:
        module = importlib.import_module(record["primitive"]["proposed_module"])
        assert hasattr(module, record["primitive"]["proposed_class"])


def test_generated_function_parameter_indexes_are_deterministic():
    indexes = []
    for category in ("block_functions", "functions"):
        indexes.extend((ROOT / f"src/claasp_next/primitives/{category}/data").glob("*.index.json"))
    # Trivium has a native typed implementation; the other families use
    # deterministic frozen catalogue specifications.
    assert len(indexes) == 14
    for path in indexes:
        variants = json.loads(path.read_text(encoding="utf-8"))["variants"]
        assert variants
        assert all(json.dumps(json.loads(key), sort_keys=True, separators=(",", ":")) == key
                   for key in variants)
