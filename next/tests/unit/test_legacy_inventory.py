"""Regression tests for the exhaustive legacy migration inventory."""

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "next" / "tools" / "legacy_inventory.py"
INVENTORY = ROOT / "next" / "migration" / "legacy_inventory.json"


def _module():
    spec = importlib.util.spec_from_file_location("legacy_inventory", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_checked_in_inventory_exactly_matches_legacy_python_tree():
    module = _module()
    assert INVENTORY.read_text(encoding="utf-8") == module.serialized_inventory()


def test_inventory_has_complete_required_metadata_and_valid_dispositions():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    required = {
        "path", "kind", "responsibility", "public_entry_points", "dependencies",
        "tests", "fixed_evidence", "v5_destination", "prerequisites", "disposition",
        "status", "acceptance_criterion", "rationale",
    }
    dispositions = {"migrate", "supersede", "defer", "remove", "inapplicable"}
    paths = [record["path"] for record in payload["records"]]
    assert paths == sorted(paths)
    assert len(paths) == len(set(paths)) == payload["counts"]["total"]
    for record in payload["records"]:
        assert required <= record.keys()
        assert record["disposition"] in dispositions
        assert record["v5_destination"]
        if record["disposition"] != "migrate":
            assert record["rationale"]


def test_every_primitive_record_has_naming_and_taxonomy_metadata():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    categories = {
        "permutations", "functions", "block_ciphers", "block_functions",
        "tweakable_block_ciphers", "tweakable_block_functions",
        "single_component_primitives", "toy_primitives",
    }
    primitive_records = [record for record in payload["records"] if "primitive" in record]
    assert primitive_records
    for record in primitive_records:
        metadata = record["primitive"]
        assert metadata["primitive_category"] in categories
        assert metadata["official_name"]
        assert metadata["proposed_module"].startswith("claasp_next.primitives.")
        assert metadata["proposed_class"]


def test_m10_8d_boolean_constraint_entries_are_resolved():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    records = {record["path"]: record for record in payload["records"]}

    source = records["claasp/cipher_modules/models/algebraic/constraints.py"]
    assert source["disposition"] == "supersede"
    assert source["status"] == "superseded-in-m10.8d"
    assert source["prerequisites"] == []
    assert source["v5_destination"].endswith("/polynomial/boolean.py")

    tests = records["tests/unit/cipher_modules/models/algebraic/constraints_test.py"]
    assert tests["disposition"] == "migrate"
    assert tests["status"] == "migrated-in-m10.8d"
    assert tests["prerequisites"] == []
