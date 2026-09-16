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
        "single_component_primitives", "toy_primitives", "outside_scope",
    }
    primitive_records = [record for record in payload["records"] if "primitive" in record]
    assert primitive_records
    for record in primitive_records:
        metadata = record["primitive"]
        assert metadata["primitive_category"] in categories
        assert metadata["official_name"]
        assert metadata["proposed_module"].startswith("claasp_next.primitives.")
        assert metadata["proposed_class"]


def test_m10_9b_catalogue_classification_is_complete_and_checks_input_roles():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    records = {record["path"]: record for record in payload["records"]}
    status = _module().catalogue_classification_status(payload)

    assert status == {
        "total": 149,
        "classified": 149,
        "categories": {
            "block_ciphers": 61,
            "block_functions": 8,
            "functions": 7,
            "outside_scope": 4,
            "permutations": 27,
            "single_component_primitives": 26,
            "toy_primitives": 7,
            "tweakable_block_ciphers": 9,
        },
        "errors": [],
        "complete": True,
    }
    assert records["claasp/ciphers/block_ciphers/mantis_block_cipher.py"]["primitive"]["primitive_category"] == "tweakable_block_ciphers"
    assert records["claasp/ciphers/permutations/tinyjambu_permutation.py"]["primitive"]["primitive_category"] == "block_ciphers"
    assert records["claasp/ciphers/stream_ciphers/bluetooth_stream_cipher_e0.py"]["primitive"]["primitive_category"] == "functions"
    helper = records["claasp/ciphers/block_ciphers/lowmc_generate_matrices.py"]
    assert helper["primitive"]["primitive_category"] == "outside_scope"
    assert helper["disposition"] == "inapplicable"


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


def test_m10_8d_algebraic_inventory_has_no_unspecified_destinations():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    records = [
        record for record in payload["records"]
        if "/models/algebraic/" in record["path"]
    ]

    assert records
    assert all("destination finalized" not in record["v5_destination"] for record in records)
    assert all(record["status"] != "planned-or-partially-migrated" for record in records)


def test_m10_8d_smt_inventory_is_resolved_with_complete_linear_evidence():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    records = [record for record in payload["records"] if "/models/smt/" in record["path"]]

    assert records
    assert all("destination finalized" not in record["v5_destination"] for record in records)
    assert all(record["status"] != "planned-or-partially-migrated" for record in records)
    deferred = {record["path"] for record in records if record["disposition"] == "defer"}
    assert deferred == set()
    linear = next(record for record in records if record["path"].endswith("smt_xor_linear_model_test.py"))
    assert linear["status"] == "migrated-in-m10.8d"
    assert linear["prerequisites"] == []


def test_m10_8d_cms_inventory_has_explicit_evidence_and_existing_destinations():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    records = [record for record in payload["records"]
               if "/cms_models/" in record["path"] and not record["path"].endswith("/__init__.py")]
    assert len(records) == 8
    assert all(record["prerequisites"] == [] for record in records)
    assert all(record["status"] in {"migrated-in-m10.8d", "superseded-in-m10.8d"} for record in records)
    assert all((ROOT / record["v5_destination"]).exists() for record in records)
    assert sum(record["disposition"] == "migrate" for record in records) == 2


def test_model_closure_requires_every_entry_to_have_a_final_disposition():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    status = _module().model_closure_status(payload)
    assert status["complete"]
    assert status["total"] == status["resolved"] + len(status["unresolved"])
    assert status["total"] == status["resolved"] == 149
    assert status["unresolved"] == []
    assert status["deferred"] == []
    assert status["remaining_by_family"] == {}
    assert _module().model_closure_status({"records": []})["complete"]


def test_m10_9c_component_catalogue_audit_has_explicit_slice_ownership():
    payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
    status = _module().component_catalogue_audit_status(payload)

    assert status["total"] == 77
    assert status["source"] == 44
    assert status["test"] == 33
    assert status["package_markers"] == 2
    assert status["behavioral"] == 75
    assert status["test_functions"] == 252
    assert status["by_slice"] == {
        "M10.9c2": 17,
        "M10.9c3": 12,
        "M10.9c4": 12,
        "M10.9c5": 18,
        "M10.9c6": 4,
        "M10.9c7": 2,
        "M10.9c8": 10,
    }
    assert status["missing"] == []
    assert status["unexpected_owners"] == []
    assert status["owner_errors"] == []
    assert len(status["unresolved"]) == 10
    assert not status["complete"]
