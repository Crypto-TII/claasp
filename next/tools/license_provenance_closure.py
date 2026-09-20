"""Validate the M11 license-provenance decision and shipped artifacts."""

from __future__ import annotations

import argparse
import ast
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
MANIFEST = ROOT / "migration" / "m11_license_provenance.json"
APPROVED_STATUSES = {"approved-apache-2.0", "approved-mit"}


def release_files() -> list[str]:
    """Return deterministic files shipped from the v5 package source tree."""

    package = ROOT / "src" / "claasp_next"
    return sorted(
        path.relative_to(package).as_posix()
        for path in package.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    )


def classify_artifact(path: str) -> str | None:
    """Return the authoritative license class for one shipped relative path."""

    if path.endswith(".py"):
        return "python-source"
    if path.startswith("primitives/block_ciphers/lowmc/data/") and path.endswith(".dat"):
        return "lowmc-parameter-data"
    if path == "catalogue/data/catalogue.json":
        return "generated-catalogue"
    if path == "primitives/permutations/poseidon/data/poseidon_bn254_width3.json":
        return "poseidon-parameter-data"
    if path == "primitives/permutations/poseidon/data/NOTICE.md":
        return "poseidon-notice"
    return None


def _sage_import_count(paths: list[str]) -> int:
    count = 0
    for path in paths:
        if not path.endswith(".py"):
            continue
        tree = ast.parse((ROOT / "src" / "claasp_next" / path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            count += sum(name == "sage" or name.startswith("sage.") for name in names)
    return count


def validate_manifest(manifest: dict[str, object], files: list[str] | None = None) -> list[str]:
    """Return deterministic closure violations for one license authority."""

    errors: list[str] = []
    if manifest.get("schema_version") != 1 or manifest.get("milestone") != "M11.2":
        errors.append("manifest identity or schema is invalid")

    current_license = manifest.get("current_license")
    decision = manifest.get("decision")
    if current_license != "GPL-3.0-or-later" or not isinstance(decision, dict):
        errors.append("current license decision is invalid")
    else:
        status = decision.get("status")
        approval = decision.get("approval_evidence")
        if status not in {"retain-gpl-pending-legal-review", *APPROVED_STATUSES}:
            errors.append("license decision status is invalid")
        if status in APPROVED_STATUSES and not approval:
            errors.append("relicensing approval has no written evidence")
        if status == "retain-gpl-pending-legal-review" and approval:
            errors.append("pending decision must not claim approval evidence")

    license_text = (REPOSITORY / "LICENSE").read_text(encoding="utf-8")
    if "GNU GENERAL PUBLIC LICENSE" not in license_text or "Version 3" not in license_text:
        errors.append("root GPLv3 license text is missing")
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    if isinstance(decision, dict) and decision.get("status") == "retain-gpl-pending-legal-review":
        if pyproject["project"].get("license") != "GPL-3.0-or-later":
            errors.append("package metadata changed before legal approval")

    evidence = manifest.get("evidence")
    if not isinstance(evidence, list) or evidence != sorted(set(evidence)):
        errors.append("evidence paths must be unique and sorted")
    else:
        for item in evidence:
            if not isinstance(item, str) or not (ROOT / item).resolve().exists():
                errors.append(f"missing evidence path: {item!r}")

    actual_files = release_files() if files is None else files
    classifications: dict[str, int] = {}
    for path in actual_files:
        category = classify_artifact(path)
        if category is None:
            errors.append(f"unclassified shipped artifact: {path}")
        else:
            classifications[category] = classifications.get(category, 0) + 1
    classes = manifest.get("artifact_classes")
    if not isinstance(classes, list):
        errors.append("artifact classes are missing")
    else:
        expected = {
            item.get("name"): item.get("count") for item in classes if isinstance(item, dict)
        }
        if len(expected) != len(classes) or expected != classifications:
            errors.append("artifact class names or counts are stale")
        for item in classes:
            if (
                not isinstance(item, dict)
                or not item.get("provenance")
                or not item.get("license_treatment")
            ):
                errors.append("artifact class lacks provenance or license treatment")
    if manifest.get("shipped_artifact_count") != len(actual_files):
        errors.append("shipped artifact count is stale")

    notice = (ROOT / "src/claasp_next/primitives/permutations/poseidon/data/NOTICE.md").read_text(
        encoding="utf-8"
    )
    if "MIT License" not in notice or "5194eadce26b3fe4b1c4fe2a5ca9f6436f3b0e3d" not in notice:
        errors.append("Poseidon third-party notice is incomplete")

    sage = manifest.get("sage_dependency_finding")
    imports = _sage_import_count(actual_files)
    if sage != {
        "declared_runtime_dependency": False,
        "imports_in_v5_release_source": imports,
        "relicensing_effect": "none",
    }:
        errors.append("Sage dependency finding is stale or claims a relicensing effect")
    if pyproject["project"].get("dependencies"):
        errors.append("v5 runtime dependency list is no longer empty")

    contribution = manifest.get("contribution_provenance")
    if not isinstance(contribution, dict) or contribution.get("committed_cla_or_dco") is not False:
        errors.append("CLA/DCO finding is missing or unsupported")
    requirements = manifest.get("legal_approval_requirements")
    if not isinstance(requirements, list) or len(requirements) != 5:
        errors.append("legal approval requirements are incomplete")
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
        "M11 license provenance passes: "
        f"{manifest['shipped_artifact_count']} artifacts; "
        f"decision {manifest['decision']['status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
