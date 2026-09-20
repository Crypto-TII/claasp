#!/usr/bin/env python3
"""Validate the private CLAASP 5 release-candidate evidence and archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "migration" / "m11_private_release_candidate.json"
FORBIDDEN_PARTS = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "migration",
    "tests",
    "tools",
}


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _archive_names(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return archive.getnames()
    raise ValueError(f"unsupported distribution archive: {path.name}")


def audit_archive(path: Path, *, version: str = "5.0.0rc1") -> list[str]:
    """Return safety and ownership violations for one distribution archive."""

    errors: list[str] = []
    try:
        names = _archive_names(path)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as error:
        return [str(error)]
    if len(names) != len(set(names)):
        errors.append(f"archive contains duplicate names: {path.name}")
    for name in names:
        member = PurePosixPath(name)
        if member.is_absolute() or ".." in member.parts:
            errors.append(f"archive contains unsafe path: {name}")
        if FORBIDDEN_PARTS.intersection(member.parts) or name.endswith((".pyc", ".pyo")):
            errors.append(f"archive contains development artifact: {name}")
    if path.suffix == ".whl":
        allowed = ("claasp/", f"claasp-{version}.dist-info/")
        if any(not name.startswith(allowed) for name in names):
            errors.append("wheel contains a path outside claasp and its dist-info")
    else:
        root = f"claasp-{version}"
        if any(PurePosixPath(name).parts[0] != root for name in names if name):
            errors.append("sdist has an unexpected top-level directory")
    return errors


def validate_manifest(manifest: dict[str, Any], *, root: Path = ROOT) -> list[str]:
    """Return deterministic violations for the M11.7 authority."""

    errors: list[str] = []
    if manifest.get("schema_version") != 1 or manifest.get("milestone") != "M11.7":
        errors.append("manifest identity or schema is invalid")
    source = manifest.get("candidate_source")
    if not isinstance(source, dict) or source.get("version") != "5.0.0rc1":
        errors.append("candidate source version is invalid")
    else:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        if project.get("version") != source["version"]:
            errors.append("candidate version differs from package metadata")

    images = manifest.get("images")
    if not isinstance(images, list) or [row.get("architecture") for row in images] != [
        "linux/amd64",
        "linux/arm64",
    ]:
        errors.append("image evidence must cover sorted amd64 and arm64 entries")
    else:
        for row in images:
            if not all(
                _digest(row.get(field))
                for field in ("config_digest", "image_digest", "manifest_digest")
            ):
                errors.append(f"image digests are invalid: {row.get('architecture')}")
            if not isinstance(row.get("size"), int) or row["size"] <= 0:
                errors.append(f"image size is invalid: {row.get('architecture')}")

    matrix = manifest.get("matrix")
    expected_counts = {
        "dependency_free": 1740,
        "developer_guide_doctests": 522,
        "external": 86,
        "failures": 0,
        "module_doctests": 636,
        "skips": 0,
        "timeouts": 0,
        "typing_reviewed_diagnostics": 900,
        "typing_suppressions": 0,
        "user_guide_doctests": 424,
        "warnings": 0,
    }
    if matrix != expected_counts:
        errors.append("release matrix counts or zero-failure claims are stale")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or [row.get("type") for row in artifacts] != [
        "wheel",
        "sdist",
    ]:
        errors.append("candidate artifacts must contain one wheel and one sdist")
    else:
        for row in artifacts:
            digest = row.get("sha256")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                errors.append(f"artifact digest is invalid: {row.get('filename')}")
            if not isinstance(row.get("entries"), int) or row["entries"] <= 0:
                errors.append(f"artifact entry count is invalid: {row.get('filename')}")

    publication = manifest.get("publication")
    if not isinstance(publication, dict) or any(publication.values()):
        errors.append("private candidate must not record public publication")
    staging = manifest.get("staging")
    if not isinstance(staging, dict):
        errors.append("private staging record is missing")
    elif (
        staging.get("visibility") != "private"
        or staging.get("secret_values_committed") is not False
        or staging.get("policies_prepared") is not True
        or staging.get("application_status") != "blocked-by-destination-prerequisites"
        or staging.get("image_registry_visibility") != "private"
        or staging.get("documentation_visibility") != "private-preview-only"
        or staging.get("package_staging") != "local-artifacts-only"
        or staging.get("secret_inventory_status") != "pending-owner-provisioning"
    ):
        errors.append("private staging boundary is unsafe or stale")
    elif staging.get("branch_policy") != {
        "default_branch": "claasp-v5",
        "force_pushes": False,
        "required_approvals": 1,
        "required_checks": ["CLAASP 5 quality", "CLAASP 5 release image"],
    }:
        errors.append("private staging branch policy is incomplete")

    paths = manifest.get("evidence_paths")
    if not isinstance(paths, list) or paths != sorted(set(paths)):
        errors.append("evidence paths must be unique and sorted")
    else:
        for relative in paths:
            if not isinstance(relative, str) or not (root / relative).is_file():
                errors.append(f"candidate evidence path is missing: {relative}")

    workflows = (
        root / ".github" / "workflows" / "claasp-quality.yaml",
        root / "docker" / "v5" / "check.sh",
    )
    command = "python tools/private_release_candidate_closure.py --check"
    for path in workflows:
        if path.exists() and command not in path.read_text(encoding="utf-8"):
            errors.append(f"private-candidate gate is missing from {path.relative_to(root)}")
    return errors


def validate_candidate_artifacts(paths: list[Path], manifest: dict[str, Any]) -> list[str]:
    """Validate exact captured candidate files against recorded evidence."""

    errors: list[str] = []
    records = {row["filename"]: row for row in manifest["artifacts"]}
    if sorted(path.name for path in paths) != sorted(records):
        return ["candidate artifact filenames differ from the authority"]
    for path in paths:
        record = records[path.name]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != record["sha256"]:
            errors.append(f"candidate artifact digest differs: {path.name}")
        try:
            count = len(_archive_names(path))
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as error:
            errors.append(str(error))
            continue
        if count != record["entries"] or path.stat().st_size != record["size"]:
            errors.append(f"candidate artifact size or entry count differs: {path.name}")
        errors.extend(audit_archive(path, version=manifest["candidate_source"]["version"]))
    return errors


def audit_distribution_set(paths: list[Path], *, version: str) -> list[str]:
    """Audit one freshly built wheel/sdist pair without requiring byte identity."""

    expected = {
        f"claasp-{version}-py3-none-any.whl",
        f"claasp-{version}.tar.gz",
    }
    if {path.name for path in paths} != expected:
        return ["fresh distribution set must contain the canonical wheel and sdist names"]
    errors: list[str] = []
    for path in paths:
        errors.extend(audit_archive(path, version=version))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--artifacts", nargs="*", type=Path, default=[])
    parser.add_argument("--candidate-artifacts", nargs="*", type=Path, default=[])
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("pass --check")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errors = validate_manifest(manifest)
    if args.artifacts:
        errors.extend(
            audit_distribution_set(args.artifacts, version=manifest["candidate_source"]["version"])
        )
    if args.candidate_artifacts:
        errors.extend(validate_candidate_artifacts(args.candidate_artifacts, manifest))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        "M11.7 private release candidate passes: 2 images, 2 distributions, 1826 tests per architecture"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
