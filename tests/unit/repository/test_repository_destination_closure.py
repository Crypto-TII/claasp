"""Tests for the M11 destination and preservation authority."""

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
    / "repository_destination_closure.py"
)
SPEC = importlib.util.spec_from_file_location("repository_destination_closure", TOOL_PATH)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


def _manifest() -> dict[str, object]:
    return json.loads(closure.MANIFEST.read_text(encoding="utf-8"))


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def test_committed_repository_destination_authority_passes():
    assert closure.validate_manifest(_manifest()) == []


def test_destination_gate_rejects_star_destroying_visibility_change():
    manifest = _manifest()
    source = dict(_mapping(manifest["source_repository"]))
    source["visibility"] = "private"
    manifest["source_repository"] = source
    invariants = dict(_mapping(manifest["launch_invariants"]))
    invariants["change_source_visibility"] = True
    manifest["launch_invariants"] = invariants

    errors = closure.validate_manifest(manifest)

    assert any("remain public" in error for error in errors)
    assert any("unsafe" in error for error in errors)


def test_destination_gate_rejects_final_name_staging_and_one_owner():
    manifest = _manifest()
    destination = dict(_mapping(manifest["destination"]))
    destination["staging_repository_name"] = "claasp"
    destination["minimum_owners"] = 1
    manifest["destination"] = destination

    errors = closure.validate_manifest(manifest)

    assert any("staging" in error for error in errors)
    assert any("two owners" in error for error in errors)


def test_destination_gate_rejects_unreviewed_affiliated_repository():
    manifest = _manifest()
    items = manifest["affiliated_repository_candidates"]
    assert isinstance(items, list)
    repositories = [dict(_mapping(item)) for item in items]
    repositories[1]["target_visibility_before_launch"] = "public"
    repositories.append(dict(repositories[1]))
    manifest["affiliated_repository_candidates"] = repositories

    errors = closure.validate_manifest(manifest)

    assert any("unique" in error for error in errors)
    assert any("not private" in error for error in errors)


def test_destination_gate_rejects_scope_expansion():
    manifest = _manifest()
    items = manifest["affiliated_repository_candidates"]
    assert isinstance(items, list)
    repositories = [dict(_mapping(item)) for item in items]
    repositories[-1]["source_full_name"] = "Crypto-TII/claasp-pro"
    manifest["affiliated_repository_candidates"] = repositories

    assert any("confirmed authority" in error for error in closure.validate_manifest(manifest))
