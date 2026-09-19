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
        "claasp/cipher.py", "tests/unit/cipher_test.py", "tests/benchmark/cipher_test.py",
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
        assert item["status"] in {
            "migrated-in-m10.15f", "superseded-in-m10.15d", "superseded-in-m10.15f",
        }
        assert item["disposition"] in {"migrate", "supersede"}
        assert item["v5_destination"].startswith("next/")
        assert item["rationale"] and item["acceptance_criterion"]


def test_evaluation_and_continuous_helpers_have_final_nonduplicating_dispositions():
    inventory = json.loads(
        (NEXT_ROOT / "migration/legacy_inventory.json").read_text(encoding="utf-8")
    )
    records = {item["path"]: item for item in inventory["records"]}
    m10_15_helpers = {
        "claasp/cipher_modules/evaluator.py",
        "claasp/cipher_modules/generic_functions.py",
        "claasp/cipher_modules/generic_functions_continuous_diffusion_analysis.py",
        "claasp/cipher_modules/generic_functions_vectorized_bit.py",
        "claasp/cipher_modules/generic_functions_vectorized_byte.py",
        "tests/unit/cipher_modules/generic_functions_test.py",
        "tests/unit/cipher_modules/generic_functions_continuous_diffusion_analysis_test.py",
        "tests/unit/cipher_modules/generic_functions_vectorized_bit_test.py",
        "tests/unit/cipher_modules/generic_functions_vectorized_byte_test.py",
    }
    for path in m10_15_helpers:
        assert records[path]["status"] == "superseded-in-m10.15d"
        assert records[path]["milestone_owner"] == "M10.15a"
    for path in {
        "claasp/cipher_modules/continuous_diffusion_analysis.py",
        "tests/unit/cipher_modules/continuous_diffusion_analysis_test.py",
    }:
        assert records[path]["milestone_owner"] == "M10.6d6"
        assert records[path]["status"] == "superseded-in-m10.15d-audit"


def test_batch_and_serialization_imports_do_not_load_numpy():
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-c", "import sys; before=set(sys.modules); import claasp_next.serialization; import claasp_next.representations.execution.batch; print('numpy' in set(sys.modules)-before)"],
        check=True, capture_output=True, text=True,
    )
    assert completed.stdout == "False\n"


def test_tooling_closure_gate_passes():
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, str(NEXT_ROOT / "tools/legacy_inventory.py"), "--check-tooling-closure"],
        check=True, capture_output=True, text=True,
    )
    status = json.loads(completed.stdout)
    assert status["complete"]
    assert status["records"] == status["final_records"] == 11
    assert status["native_artifacts"] == 4
    assert status["continuous_m10_6d6_retained"]
