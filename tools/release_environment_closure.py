"""Validate the pinned multi-architecture CLAASP 5 release environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT
MANIFEST = ROOT / "migration" / "m11_release_environment.json"
LOCK_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+==[^=\s]+$")


def validate_manifest(manifest: dict[str, object]) -> list[str]:
    """Return deterministic violations in one release-environment authority."""

    errors: list[str] = []
    if manifest.get("schema_version") != 1 or manifest.get("milestone") != "M11.3":
        errors.append("manifest identity or schema is invalid")
    if manifest.get("architecture_matrix") != ["linux/amd64", "linux/arm64"]:
        errors.append("architecture matrix must cover amd64 and arm64")
    if manifest.get("python") != "3.12.3":
        errors.append("canonical Python version is stale")

    publication = manifest.get("publication")
    if not isinstance(publication, dict):
        errors.append("publication policy is missing")
    elif publication.get("allowed_registry_visibility") != "private":
        errors.append("release image publication is not private-only")
    elif publication.get("published") and not publication.get("registry"):
        errors.append("published image lacks a private registry identity")

    paths: dict[str, Path] = {}
    for field in ("dockerfile", "python_lock", "validation_script", "workflow"):
        value = manifest.get(field)
        if not isinstance(value, str):
            errors.append(f"{field} path is missing")
            continue
        path = (ROOT / value).resolve()
        paths[field] = path
        if not path.is_file():
            errors.append(f"missing {field}: {value}")

    lock_path = paths.get("python_lock")
    if lock_path and lock_path.is_file():
        entries = [
            line
            for line in lock_path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        if not entries or any(not LOCK_PATTERN.fullmatch(line) for line in entries):
            errors.append("Python lock contains an unpinned or malformed entry")
        names = [line.partition("==")[0].lower().replace("_", "-") for line in entries]
        if len(names) != len(set(names)):
            errors.append("Python lock contains duplicate package identities")
        if manifest.get("python_lock_entries") != len(entries):
            errors.append("Python lock entry count is stale")

    dockerfile_path = paths.get("dockerfile")
    if dockerfile_path and dockerfile_path.is_file():
        dockerfile = dockerfile_path.read_text(encoding="utf-8")
        required = [
            str(manifest.get("base_image")),
            "--no-deps -r /tmp/requirements.lock",
            "CHUFFED_SHA256=",
            "MSOLVE_SHA256=",
            "NIST_STS_SHA256=",
            "minizinc-wrapper.sh /usr/local/bin/minizinc",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONPATH=/workspace/src",
        ]
        for value in required:
            if value not in dockerfile:
                errors.append(f"Dockerfile release invariant is missing: {value}")
        if re.search(r"(?:^|[ /])sage(?:math)?(?:[ =]|$)", dockerfile, re.IGNORECASE):
            errors.append("canonical release image contains Sage")
        source_builds = manifest.get("source_builds")
        if not isinstance(source_builds, dict):
            errors.append("source-build authority is missing")
        else:
            for name, record in source_builds.items():
                if not isinstance(record, dict):
                    errors.append(f"invalid source-build record: {name}")
                    continue
                version = record.get("version")
                sha256 = record.get("sha256")
                if (
                    not isinstance(version, str)
                    or version not in dockerfile
                    or not isinstance(sha256, str)
                    or sha256 not in dockerfile
                ):
                    errors.append(f"source build is not pinned in Dockerfile: {name}")

    patch_files = manifest.get("nist_patch_files")
    if not isinstance(patch_files, dict) or len(patch_files) != 3:
        errors.append("NIST patch-file authority is missing")
    else:
        for relative, expected_digest in sorted(patch_files.items()):
            if not isinstance(relative, str) or not isinstance(expected_digest, str):
                errors.append("NIST patch-file record is malformed")
                continue
            path = ROOT / relative
            if not path.is_file():
                errors.append(f"NIST patch file is missing: {relative}")
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != expected_digest:
                errors.append(f"NIST patch digest is stale: {relative}")
            if dockerfile_path and relative not in dockerfile_path.read_text(encoding="utf-8"):
                errors.append(f"NIST patch is not copied by the Dockerfile: {relative}")

    workflow_path = paths.get("workflow")
    if workflow_path and workflow_path.is_file():
        workflow = workflow_path.read_text(encoding="utf-8")
        for value in (
            "linux/amd64",
            "linux/arm64",
            "not external and not performance",
            "external and not emulation_sensitive",
            "CLAASP_DEPENDENCY_FREE_EXPRESSION",
            "CLAASP_EXTERNAL_EXPRESSION",
            "docker/v5/check.sh",
            "push: false",
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130",
            "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
            "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
        ):
            if value not in workflow:
                errors.append(f"release-image workflow invariant is missing: {value}")

    check_path = paths.get("validation_script")
    if check_path and check_path.is_file():
        check = check_path.read_text(encoding="utf-8")
        for value in (
            "-m 'not external'",
            "CLAASP_DEPENDENCY_FREE_EXPRESSION",
            "CLAASP_EXTERNAL_EXPRESSION",
            "-m external",
            "--doctest-modules",
            "make -C docs doctest",
            "make -C docs html",
            "ruff format --check",
            "typecheck_closure.py --check",
            "wheel_audit.py",
        ):
            if value not in check:
                errors.append(f"release validation command is missing: {value}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("pass --check")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errors = validate_manifest(manifest)
    if errors:
        print("\n".join(errors))
        return 1
    print(
        "M11 release environment passes: "
        f"{len(manifest['architecture_matrix'])} architectures, "
        f"Python {manifest['python']}, {manifest['python_lock_entries']} locked packages"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
