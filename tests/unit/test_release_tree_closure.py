"""Tests for the M11.6 release-tree closure gate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "release_tree_closure.py"
SPEC = importlib.util.spec_from_file_location("release_tree_closure", TOOL_PATH)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


def _manifest() -> dict[str, object]:
    return json.loads(closure.MANIFEST.read_text(encoding="utf-8"))


def test_committed_release_tree_authority_passes():
    assert closure.validate_manifest(_manifest()) == []


def test_release_tree_rejects_old_identity_and_missing_gate(tmp_path: Path):
    manifest = _manifest()
    manifest["required_release_paths"] = ["src/claasp/__init__.py"]
    manifest["forbidden_legacy_surfaces"] = []
    (tmp_path / "src" / "claasp").mkdir(parents=True)
    (tmp_path / "src" / "claasp" / "__init__.py").write_text(
        '"""claasp_next compatibility."""\n', encoding="utf-8"
    )

    errors = closure.validate_manifest(manifest, root=tmp_path)

    assert any("old package identity" in error for error in errors)


def test_release_tree_rejects_stale_m11a_counts():
    manifest = _manifest()
    authority_counts = manifest["m11a"]
    assert isinstance(authority_counts, dict)
    counts = dict(authority_counts)
    counts["v5_artifacts"] = 1
    manifest["m11a"] = counts

    errors = closure.validate_manifest(manifest)

    assert "post-rename M11a counts are stale" in errors
