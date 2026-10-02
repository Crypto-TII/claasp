import importlib
import json
from pathlib import Path

ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file()
)


def test_every_m10_9d7_source_has_its_typed_public_class():
    inventory = json.loads((ROOT / "migration/legacy_inventory.json").read_text(encoding="utf-8"))
    records = [
        record
        for record in inventory["records"]
        if record.get("milestone_owner") == "M10.9d7" and record["kind"] == "source"
    ]
    assert len(records) == 25
    for record in records:
        module = importlib.import_module(record["primitive"]["proposed_module"])
        assert hasattr(module, record["primitive"]["proposed_class"])


def test_permutation_implementations_are_readable_native_sources():
    root = ROOT / "src/claasp/primitives/permutations"
    assert not tuple(root.glob("*/data/index.json"))
    assert not tuple(root.glob("*/data/*.json.gz"))
    assert "class Xoodoo" in (root / "xoodoo/primitive.py").read_text(encoding="utf-8")
