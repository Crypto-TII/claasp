"""Tests for the M11.4 upstream-reconciliation closure gate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

TOOL_PATH = (
    next(
        parent
        for parent in Path(__file__).resolve().parents
        if (parent / "pyproject.toml").is_file()
    )
    / "tools/upstream_reconciliation_closure.py"
)
SPEC = importlib.util.spec_from_file_location("upstream_reconciliation_closure", TOOL_PATH)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


def _manifest():
    return json.loads(closure.MANIFEST.read_text(encoding="utf-8"))


def test_committed_upstream_reconciliation_passes():
    assert closure.validate_manifest(_manifest()) == []


def test_reconciliation_rejects_missing_commit_and_merge_policy():
    manifest = _manifest()
    manifest["records"] = manifest["records"][:-1]
    manifest["merge_policy"] = "merge-develop"
    errors = closure.validate_manifest(manifest)
    assert any("coverage or order" in error for error in errors)
    assert any("merge policy" in error for error in errors)


def test_reconciliation_rejects_invalid_disposition_and_rationale():
    manifest = _manifest()
    manifest["records"][0]["disposition"] = "ignored"
    manifest["records"][0]["rationale"] = "later"
    errors = closure.validate_manifest(manifest)
    assert any("invalid disposition" in error for error in errors)
    assert any("substantive rationale" in error for error in errors)


def test_reconciliation_rejects_duplicate_or_missing_evidence():
    manifest = _manifest()
    manifest["records"][0]["evidence"] = ["missing.py", "missing.py"]
    errors = closure.validate_manifest(manifest)
    assert any("duplicate evidence" in error for error in errors)


def test_reconciliation_keeps_final_freeze_open():
    manifest = _manifest()
    manifest["final_reconciliation_boundary"] = "complete"

    assert any("future CLAASP 4 freeze" in error for error in closure.validate_manifest(manifest))
