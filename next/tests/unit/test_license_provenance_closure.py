"""Tests for the M11 license-provenance closure gate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "license_provenance_closure.py"
SPEC = importlib.util.spec_from_file_location("license_provenance_closure", TOOL_PATH)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


def _manifest() -> dict[str, object]:
    return json.loads(closure.MANIFEST.read_text(encoding="utf-8"))


def test_committed_license_provenance_authority_passes():
    assert closure.validate_manifest(_manifest()) == []


def test_license_gate_rejects_relicensing_without_written_evidence():
    manifest = _manifest()
    decision = dict(manifest["decision"])
    decision["status"] = "approved-mit"
    manifest["decision"] = decision

    errors = closure.validate_manifest(manifest)

    assert any("no written evidence" in error for error in errors)


def test_license_gate_rejects_unclassified_and_stale_artifacts():
    manifest = _manifest()
    files = closure.release_files() + ["data/unreviewed.bin"]

    errors = closure.validate_manifest(manifest, files)

    assert any("unclassified shipped artifact" in error for error in errors)
    assert any("artifact count is stale" in error for error in errors)


def test_license_gate_rejects_stale_classification():
    manifest = _manifest()
    classes = [dict(item) for item in manifest["artifact_classes"]]
    classes[0]["count"] -= 1
    manifest["artifact_classes"] = classes

    assert any("counts are stale" in error for error in closure.validate_manifest(manifest))


def test_sage_removal_is_not_relicensing_authority():
    manifest = _manifest()
    sage = dict(manifest["sage_dependency_finding"])
    sage["relicensing_effect"] = "permits-mit"
    manifest["sage_dependency_finding"] = sage

    assert any("relicensing effect" in error for error in closure.validate_manifest(manifest))
