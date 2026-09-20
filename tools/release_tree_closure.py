"""Validate the promoted CLAASP 5 release tree and package identity."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "migration" / "m11_release_tree.json"
MIGRATION_MATRIX = ROOT / "migration" / "m11a_bidirectional_migration.json"
ACTIVE_TEXT_ROOTS = (
    ROOT / "src",
    ROOT / "tests",
    ROOT / "tools",
    ROOT / "docs",
    ROOT / "docker",
    ROOT / ".github" / "workflows",
)
ACTIVE_TEXT_FILES = (ROOT / "README.md", ROOT / "Makefile", ROOT / "pyproject.toml")
OLD_IDENTITY_EVIDENCE_PATHS = {
    Path("docs/architecture/v5-plan.md"),
    Path("docs/development.rst"),
    Path("tests/unit/test_release_tree_closure.py"),
    Path("tools/release_tree_closure.py"),
}


def _strings(value: object) -> list[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return value


def _active_files(root: Path) -> list[Path]:
    files: list[Path] = []
    relative_roots = [path.relative_to(ROOT) for path in ACTIVE_TEXT_ROOTS]
    relative_files = [path.relative_to(ROOT) for path in ACTIVE_TEXT_FILES]
    for relative in relative_roots:
        base = root / relative
        if base.exists():
            files.extend(
                path
                for path in base.rglob("*")
                if path.is_file() and "_build" not in path.relative_to(base).parts
            )
    files.extend(root / relative for relative in relative_files if (root / relative).exists())
    return sorted(set(files))


def validate_manifest(manifest: dict[str, object], *, root: Path = ROOT) -> list[str]:
    """Return deterministic violations for one release-tree authority."""

    errors: list[str] = []
    if manifest.get("schema_version") != 1 or manifest.get("milestone") != "M11.6":
        errors.append("manifest identity or schema is invalid")
    if manifest.get("distribution") != "claasp" or manifest.get("import_package") != "claasp":
        errors.append("release package identity must be claasp")

    required = _strings(manifest.get("required_release_paths"))
    if required is None or required != sorted(set(required)):
        errors.append("required release paths must be unique and sorted")
    else:
        for relative in required:
            if not (root / relative).exists():
                errors.append(f"required release path is missing: {relative}")

    forbidden = _strings(manifest.get("forbidden_legacy_surfaces"))
    if forbidden is None or forbidden != sorted(set(forbidden)):
        errors.append("forbidden legacy surfaces must be unique and sorted")
    else:
        for relative in forbidden:
            if (root / relative).exists():
                errors.append(f"legacy surface remains in the release tree: {relative}")

    preservation = manifest.get("legacy_preservation")
    if not isinstance(preservation, dict):
        errors.append("legacy preservation record is missing")
    else:
        if preservation.get("branch") != "v4-maintenance":
            errors.append("legacy preservation branch is stale")
        commit = preservation.get("commit")
        if (
            not isinstance(commit, str)
            or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
        ):
            errors.append("legacy preservation commit is invalid")
        if preservation.get("remote_line") != "origin/develop":
            errors.append("legacy preservation source line is stale")

    pyproject_path = root / "pyproject.toml"
    if pyproject_path.exists():
        project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]
        if project.get("name") != manifest.get("distribution"):
            errors.append("distribution metadata differs from the release authority")
        if project.get("version") != manifest.get("version"):
            errors.append("package version differs from the release authority")

    matrix_path = root / MIGRATION_MATRIX.relative_to(ROOT)
    if matrix_path.exists():
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        summary = matrix.get("summary", {})
        classifications = summary.get("v5_by_classification", {})
        destinations = sum(bool(row.get("destinations")) for row in matrix["legacy_records"])
        expected = {
            "legacy_records": summary.get("legacy_records"),
            "legacy_with_destinations": destinations,
            "new_v5_artifacts": classifications.get("new-v5"),
            "v5_artifacts": summary.get("v5_artifacts"),
            "v5_with_legacy_lineage": classifications.get("legacy-lineage"),
        }
        if manifest.get("m11a") != expected:
            errors.append("post-rename M11a counts are stale")

    for path in _active_files(root):
        if path.relative_to(root) in OLD_IDENTITY_EVIDENCE_PATHS:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if "claasp_next" in content or "claasp-next" in content:
            errors.append(
                f"old package identity remains in active release text: {path.relative_to(root)}"
            )

    workflow = root / ".github" / "workflows" / "claasp-quality.yaml"
    image_check = root / "docker" / "v5" / "check.sh"
    for path in (workflow, image_check):
        if path.exists() and "python tools/release_tree_closure.py --check" not in path.read_text(
            encoding="utf-8"
        ):
            errors.append(f"release-tree gate is missing from {path.relative_to(root)}")
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
        print("\n".join(errors), file=sys.stderr)
        return 1
    counts = manifest["m11a"]
    print(
        "M11.6 release-tree closure passes: "
        f"{counts['legacy_records']} legacy records, {counts['v5_artifacts']} release artifacts; "
        "distribution/import package claasp"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
