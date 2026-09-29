"""Tests for the controlled M11.8 publication preflight."""

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
    / "publication_preflight.py"
)
SPEC = importlib.util.spec_from_file_location("publication_preflight", TOOL_PATH)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


def _authorities() -> tuple[dict[str, object], dict[str, object]]:
    manifest = json.loads(preflight.MANIFEST.read_text(encoding="utf-8"))
    destination = json.loads(preflight.DESTINATION.read_text(encoding="utf-8"))
    return manifest, destination


def test_committed_publication_plan_passes():
    manifest, destination = _authorities()
    assert preflight.validate_plan(manifest, destination) == []


def test_publication_plan_rejects_replacement_repository():
    manifest, destination = _authorities()
    invariants = manifest["transfer_invariants"]
    assert isinstance(invariants, dict)
    invariants["create_replacement_for_star_bearing_repository"] = True

    errors = preflight.validate_plan(manifest, destination)

    assert "transfer invariants permit destructive publication" in errors


def test_publication_plan_rejects_premature_mutation():
    manifest, destination = _authorities()
    state = manifest["publication_state"]
    assert isinstance(state, dict)
    state["organization_created"] = True

    errors = preflight.validate_plan(manifest, destination)

    assert "preflight records an unauthorized external mutation" in errors


def test_readiness_reports_each_owned_blocker():
    manifest, _ = _authorities()

    blockers = preflight.readiness_blockers(manifest)

    assert len(blockers) == 11
    assert all(": " in blocker for blocker in blockers)
    assert any(blocker.startswith("phase-R2:") for blocker in blockers)
