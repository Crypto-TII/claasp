import json
from pathlib import Path


NEXT_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = NEXT_ROOT.parent


def test_m10_15_inventory_assigns_python_native_mixed_and_diagram_surfaces():
    manifest = json.loads(
        (NEXT_ROOT / "migration/m10_15_tooling_obligations.json").read_text(encoding="utf-8")
    )
    assert manifest["milestone"] == "M10.15"
    assert manifest["compatibility_policy"]["canonical_schema"] == "org.claasp.primitive"
    assert manifest["cuda_disposition"]["disposition"] == "out-of-scope"
    assert len(manifest["native_artifacts"]) == 4
    for item in manifest["native_artifacts"]:
        assert item["owner"].startswith("M10.15")
        assert item["disposition"] == "supersede"
        assert item["rationale"] and item["fixed_evidence"]
        assert (REPOSITORY_ROOT / item["path"]).is_file()
    assert {item["path"] for item in manifest["mixed_module_surfaces"]} == {
        "claasp/cipher.py", "tests/unit/cipher_test.py",
    }
    diagram = manifest["diagram_audit"]
    assert diagram["disposition"] == "retain-achieved-m10.5d5"
    for destination in diagram["destinations"]:
        assert (REPOSITORY_ROOT / destination).exists()


def test_m10_15_python_records_have_explicit_ownership_and_rationales():
    inventory = json.loads(
        (NEXT_ROOT / "migration/legacy_inventory.json").read_text(encoding="utf-8")
    )
    owned = [item for item in inventory["records"] if item.get("milestone_owner") == "M10.15a"]
    assert len(owned) == 11
    for item in owned:
        assert item["status"] == "owned-in-m10.15a"
        assert item["disposition"] in {"migrate", "supersede"}
        assert item["v5_destination"].startswith("next/")
        assert item["rationale"] and item["acceptance_criterion"]
