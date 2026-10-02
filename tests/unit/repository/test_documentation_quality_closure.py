"""Tests for the complete M10.16 machine closure gate."""

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
    / "tools"
    / "documentation_quality_closure.py"
)
SPEC = importlib.util.spec_from_file_location("documentation_quality_closure", TOOL_PATH)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


def test_committed_documentation_quality_authority_is_closed():
    manifest = json.loads(closure.MANIFEST.read_text(encoding="utf-8"))

    assert closure.validate_manifest(manifest) == []


def test_closure_rejects_stale_scope_versions_counts_and_evidence():
    manifest = json.loads(closure.MANIFEST.read_text(encoding="utf-8"))
    malformed = dict(manifest)
    malformed["quality_scope"] = ["src/claasp"]
    malformed["versions"] = {"ruff": "latest"}
    malformed["documentation"] = {"public_api_entries": 1}
    malformed["typing"] = {"diagnostics": 0, "inline_suppressions": 1}
    malformed["evidence"] = ["missing", "missing"]

    errors = closure.validate_manifest(malformed)

    assert any("scope" in error for error in errors)
    assert any("versions" in error for error in errors)
    assert any("documentation counts" in error for error in errors)
    assert any("typing counts" in error for error in errors)
    assert any("unique and sorted" in error for error in errors)
