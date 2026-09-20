"""Tests for the M11 canonical release-environment closure gate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "release_environment_closure.py"
SPEC = importlib.util.spec_from_file_location("release_environment_closure", TOOL_PATH)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


def _manifest() -> dict[str, object]:
    return json.loads(closure.MANIFEST.read_text(encoding="utf-8"))


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def test_committed_release_environment_authority_passes():
    assert closure.validate_manifest(_manifest()) == []
    wrapper = closure.REPOSITORY / "docker" / "v5" / "minizinc-wrapper.sh"
    assert wrapper.stat().st_mode & 0o111
    assert 'exec /usr/bin/minizinc --no-optimize "$@"' in wrapper.read_text(encoding="utf-8")


def test_release_environment_rejects_single_architecture_and_public_registry():
    manifest = _manifest()
    manifest["architecture_matrix"] = ["linux/amd64"]
    publication = dict(_mapping(manifest["publication"]))
    publication["allowed_registry_visibility"] = "public"
    manifest["publication"] = publication

    errors = closure.validate_manifest(manifest)

    assert any("amd64 and arm64" in error for error in errors)
    assert any("private-only" in error for error in errors)


def test_release_environment_rejects_stale_lock_count_and_source_digest():
    manifest = _manifest()
    manifest["python_lock_entries"] = 1
    source_builds = {
        name: dict(_mapping(record)) for name, record in _mapping(manifest["source_builds"]).items()
    }
    source_builds["msolve"]["sha256"] = "0" * 64
    manifest["source_builds"] = source_builds

    errors = closure.validate_manifest(manifest)

    assert any("entry count" in error for error in errors)
    assert any("msolve" in error for error in errors)
