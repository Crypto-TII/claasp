"""Tests for the M11.7 private release-candidate closure gate."""

from __future__ import annotations

import importlib.util
import io
import json
import tarfile
from pathlib import Path

TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "private_release_candidate_closure.py"
SPEC = importlib.util.spec_from_file_location("private_release_candidate_closure", TOOL_PATH)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


def _manifest() -> dict[str, object]:
    return json.loads(closure.MANIFEST.read_text(encoding="utf-8"))


def test_committed_private_candidate_authority_passes():
    assert closure.validate_manifest(_manifest()) == []


def test_private_candidate_rejects_publication():
    manifest = _manifest()
    publication_value = manifest["publication"]
    assert isinstance(publication_value, dict)
    publication = dict(publication_value)
    publication["package_published"] = True
    manifest["publication"] = publication

    assert "private candidate must not record public publication" in closure.validate_manifest(
        manifest
    )


def test_private_candidate_rejects_incomplete_architecture_matrix():
    manifest = _manifest()
    images = manifest["images"]
    assert isinstance(images, list)
    manifest["images"] = images[1:]

    errors = closure.validate_manifest(manifest)

    assert "image evidence must cover sorted amd64 and arm64 entries" in errors


def test_distribution_audit_rejects_development_and_unsafe_paths(tmp_path: Path):
    archive_path = tmp_path / "claasp-5.0.0rc1.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        for name in (
            "claasp-5.0.0rc1/src/claasp/__init__.py",
            "../escape",
            "claasp-5.0.0rc1/.mypy_cache/state",
        ):
            payload = b"evidence"
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    errors = closure.audit_archive(archive_path)

    assert any("unsafe path" in error for error in errors)
    assert any("development artifact" in error for error in errors)


def test_distribution_set_rejects_missing_sdist(tmp_path: Path):
    wheel = tmp_path / "claasp-5.0.0rc1-py3-none-any.whl"

    errors = closure.audit_distribution_set([wheel], version="5.0.0rc1")

    assert errors == ["fresh distribution set must contain the canonical wheel and sdist names"]
