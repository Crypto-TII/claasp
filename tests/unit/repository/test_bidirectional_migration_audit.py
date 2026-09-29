"""Tests for the M11a bidirectional migration closure gate."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

TOOL_PATH = (
    next(
        parent
        for parent in Path(__file__).resolve().parents
        if (parent / "pyproject.toml").is_file()
    )
    / "tools/bidirectional_migration_audit.py"
)
SPEC = importlib.util.spec_from_file_location("bidirectional_migration_audit", TOOL_PATH)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def _matrix():
    return json.loads(audit.MATRIX.read_text(encoding="utf-8"))


def test_committed_bidirectional_migration_audit_passes():
    matrix = _matrix()
    assert audit.validate_matrix(matrix) == []
    assert audit.render_summary(matrix) == audit.SUMMARY.read_text(encoding="utf-8")


def test_audit_rejects_missing_and_duplicate_artifacts():
    matrix = _matrix()
    matrix["v5_artifacts"] = matrix["v5_artifacts"][:-1]
    errors = audit.validate_matrix(matrix)
    assert any("artifact coverage or order" in error for error in errors)

    matrix = _matrix()
    matrix["v5_artifacts"][1] = copy.deepcopy(matrix["v5_artifacts"][0])
    errors = audit.validate_matrix(matrix)
    assert any("duplicate identities" in error for error in errors)


def test_audit_rejects_provisional_legacy_status_and_missing_destination():
    matrix = _matrix()
    matrix["legacy_records"][0]["status"] = "planned-or-partially-migrated"
    matrix["legacy_records"][0]["destinations"] = ["src/claasp/missing.py"]
    errors = audit.validate_matrix(matrix)
    assert any("disposition is not final" in error for error in errors)
    assert any("destination is missing" in error for error in errors)


def test_audit_rejects_stale_predecessor_and_unjustified_new_artifact():
    matrix = _matrix()
    record = next(item for item in matrix["v5_artifacts"] if item["classification"] == "new-v5")
    record["legacy_predecessors"] = ["claasp/missing.py"]
    record.pop("rationale")
    errors = audit.validate_matrix(matrix)
    assert any("predecessors are stale" in error for error in errors)
    assert any("rationale is missing or contradictory" in error for error in errors)


def test_audit_rejects_missing_legacy_reason_and_renders_complete_tables():
    matrix = _matrix()
    matrix["legacy_records"][0]["rationale"] = ""

    assert any("legacy reason" in error for error in audit.validate_matrix(matrix))

    rendered = audit.render_summary(_matrix())
    assert "## Complete legacy-to-v5 mapping" in rendered
    assert "## Complete v5-to-legacy mapping" in rendered
    assert rendered.count("| `claasp/") >= 500
    reverse = rendered.split("## Complete v5-to-legacy mapping", 1)[1].split(
        "## New-v5 artifact rationale groups", 1
    )[0]
    assert reverse.count("| `src/claasp/") == 408
