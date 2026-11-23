"""Each develop change has a scoped disposition and current source evidence."""

import json
from pathlib import Path


def test_review_accounts_for_changed_sources_and_evidence():
    data = Path("tools/data")
    snapshot = json.loads((data / "legacy_current_snapshot.json").read_text())
    review = json.loads((data / "develop_sync_review.json").read_text())
    hashes = {
        item["path"]: item["sha256"] for item in snapshot["python_files"] + snapshot["resources"]
    }
    assert review["source_commit"] == snapshot["source_commit"]
    rows = review["records"]
    assert len(rows) == len({item["path"] for item in rows}) == 29
    for item in rows:
        assert hashes[item["path"]] == item["sha256"]
        assert item["replacement_contract"]
        assert item["evidence"] and all(Path(path).is_file() for path in item["evidence"])
    additions = json.loads((data / "develop_sync_inventory_delta.json").read_text())["records"]
    assert len(additions) == 4
    assert {item["path"] for item in additions} <= {item["path"] for item in rows}


def test_legacy_highs_cmake_emulation_fix_is_not_needed_by_v5():
    dockerfile = Path("docker/v5/Dockerfile").read_text()
    lock = Path("docker/v5/requirements.lock").read_text()
    assert "COPY docker/v5/requirements.lock" in dockerfile
    assert "scipy==" in lock
    assert "highs-" not in dockerfile.lower()
    assert "chuffed-" in dockerfile  # The remaining native CMake build is Chuffed.
