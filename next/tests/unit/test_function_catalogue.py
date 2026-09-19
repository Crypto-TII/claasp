import importlib
import json
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_every_m10_9d8_source_has_its_typed_public_class():
    inventory = json.loads((ROOT / "migration/legacy_inventory.json").read_text(encoding="utf-8"))
    records = [
        record
        for record in inventory["records"]
        if record.get("milestone_owner") == "M10.9d8" and record["kind"] == "source"
    ]
    assert len(records) == 15
    for record in records:
        module = importlib.import_module(record["primitive"]["proposed_module"])
        assert hasattr(module, record["primitive"]["proposed_class"])


def test_function_implementations_have_no_frozen_graph_indexes():
    for category in ("block_functions", "functions"):
        root = ROOT / f"src/claasp_next/primitives/{category}"
        assert not tuple(root.glob("*/data/index.json"))
        assert not tuple(root.glob("*/data/*.json.gz"))
