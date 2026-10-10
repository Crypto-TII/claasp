import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs/architecture/audits/data/legacy-public-capability-matrix.json"


def test_every_audited_legacy_capability_has_an_executable_disposition():
    document = json.loads(MATRIX.read_text(encoding="utf-8"))
    capabilities = document["capabilities"]

    assert document["schema"] == 1
    assert len(capabilities) == 30
    assert len({item["id"] for item in capabilities}) == len(capabilities)
    assert {item["status"] for item in capabilities} == {
        "supported",
        "deliberately_removed",
    }
    assert all(item.get("api") and item.get("evidence") for item in capabilities)
    assert all((ROOT / item["evidence"]).exists() for item in capabilities)
    assert all(
        item.get("reason") for item in capabilities if item["status"] == "deliberately_removed"
    )
