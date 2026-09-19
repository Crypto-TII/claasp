import json
from pathlib import Path

NEXT_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = NEXT_ROOT.parent


def test_every_presentation_obligation_has_owned_existing_destinations_and_evidence():
    payload = json.loads(
        (NEXT_ROOT / "migration/m10_14_presentation_obligations.json").read_text(encoding="utf-8")
    )
    assert payload["milestone"] == "M10.14"
    assert len(payload["obligations"]) == 8
    for item in payload["obligations"]:
        assert item["owner"].startswith("M10.14")
        assert item["disposition"] in {"supersede", "supersede-deferred-presentation"}
        assert item["rationale"]
        assert item["fixed_evidence"]
        assert item["status"] == "achieved"
        for legacy_path in item["legacy_paths"]:
            assert (REPOSITORY_ROOT / legacy_path).exists()
        for destination in item["destinations"]:
            assert (REPOSITORY_ROOT / destination).exists()


def test_four_report_records_have_explicit_m10_14_ownership():
    inventory = json.loads(
        (NEXT_ROOT / "migration/legacy_inventory.json").read_text(encoding="utf-8")
    )
    records = {item["path"]: item for item in inventory["records"]}
    paths = {
        "claasp/cipher_modules/report.py",
        "tests/unit/cipher_modules/report_test.py",
        "claasp/cipher_modules/statistical_tests/nist_statistical_tests_report.py",
        "tests/unit/cipher_modules/statistical_tests/nist_statistical_tests_report_test.py",
    }
    for path in paths:
        record = records[path]
        assert record["milestone_owner"] == "M10.14a"
        assert record["status"] == "superseded-in-m10.14g"
        assert record["rationale"]
        assert record["acceptance_criterion"]
        assert "next/" in record["v5_destination"]
