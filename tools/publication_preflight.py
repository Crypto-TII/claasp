#!/usr/bin/env python3
"""Validate the controlled M11.8 GitHub transfer and publication preflight."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "migration" / "m11_publication_preflight.json"
DESTINATION = ROOT / "migration" / "m11_repository_destination.json"
REQUIRED_BLOCKERS = {
    "destination-handle",
    "destination-owners",
    "destination-permissions",
    "missing-source-admin",
    "repository-set-approval",
}


def validate_plan(
    manifest: dict[str, Any],
    destination: dict[str, Any],
    *,
    root: Path = ROOT,
) -> list[str]:
    """Return deterministic safety or consistency violations for the preflight."""

    errors: list[str] = []
    if manifest.get("schema_version") != 1 or manifest.get("milestone") != "M11.8-preflight":
        errors.append("preflight identity or schema is invalid")

    candidate = manifest.get("local_candidate")
    if not isinstance(candidate, dict):
        errors.append("local candidate record is missing")
    else:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        if candidate.get("version") != project.get("version"):
            errors.append("preflight version differs from package metadata")
        commit = candidate.get("commit")
        if not isinstance(commit, str) or len(commit) < 8:
            errors.append("local candidate commit is invalid")

    requested = destination.get("destination", {})
    target = manifest.get("destination")
    if not isinstance(target, dict):
        errors.append("destination preflight is missing")
    elif (
        target.get("preferred_handle") != requested.get("preferred_handle")
        or target.get("accepted_handle") is not None
        or target.get("organization_created") is not False
        or target.get("preferred_handle_kind") != "User"
    ):
        errors.append("destination state is unsafe or inconsistent")

    repositories = manifest.get("repositories")
    expected = destination.get("affiliated_repository_candidates")
    if not isinstance(repositories, list) or not isinstance(expected, list):
        errors.append("repository inventory is missing")
    else:
        names = [row.get("name") for row in repositories]
        if names != sorted(names) or len(names) != len(set(names)):
            errors.append("repository records must be unique and sorted")
        expected_by_name = {row["name"]: row for row in expected}
        if set(names) != set(expected_by_name):
            errors.append("preflight repository set differs from destination authority")
        for row in repositories:
            authority = expected_by_name.get(row.get("name"))
            if authority and (
                row.get("visibility") != authority.get("source_visibility")
                or row.get("target_visibility_before_launch")
                != authority.get("target_visibility_before_launch")
            ):
                errors.append(f"repository visibility plan is stale: {row.get('name')}")
        claasp: dict[str, Any] = next(
            (row for row in repositories if row.get("name") == "claasp"), {}
        )
        if (
            claasp.get("visibility") != "public"
            or claasp.get("target_visibility_before_launch") != "public"
            or claasp.get("stars") != 79
            or claasp.get("forks") != 14
        ):
            errors.append("star-bearing repository preservation evidence is stale")

    invariants = manifest.get("transfer_invariants")
    if invariants != {
        "change_public_source_visibility": False,
        "create_replacement_for_star_bearing_repository": False,
        "preserve_v4_maintenance_reference": True,
        "publish_before_post_transfer_audit": False,
        "transfer_existing_public_repository": True,
    }:
        errors.append("transfer invariants permit destructive publication")

    state = manifest.get("publication_state")
    if not isinstance(state, dict) or any(value is not False for value in state.values()):
        errors.append("preflight records an unauthorized external mutation")

    license_record = manifest.get("license_at_launch")
    if (
        not isinstance(license_record, dict)
        or license_record.get("approved_spdx") != "GPL-3.0-or-later"
    ):
        errors.append("launch license exceeds reviewed rights")

    blockers = manifest.get("open_blockers")
    if not isinstance(blockers, list):
        errors.append("open blocker authority is missing")
    else:
        identifiers = [row.get("id") for row in blockers]
        if set(identifiers) != REQUIRED_BLOCKERS or len(identifiers) != len(set(identifiers)):
            errors.append("open blocker set is incomplete or duplicated")
        for row in blockers:
            if not row.get("owner") or not row.get("resolution"):
                errors.append(f"blocker lacks owner or resolution: {row.get('id')}")

    actions = manifest.get("launch_actions")
    if not isinstance(actions, list) or actions[-1:] != ["complete-post-transfer-audit"]:
        errors.append("launch action order is incomplete")
    return errors


def readiness_blockers(manifest: dict[str, Any]) -> list[str]:
    """Return unresolved conditions that prevent an external launch."""

    blockers = manifest.get("open_blockers", [])
    return [f"{row['id']}: {row['resolution']}" for row in blockers]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-plan", action="store_true")
    parser.add_argument("--ready", action="store_true")
    args = parser.parse_args(argv)
    if not args.check_plan and not args.ready:
        parser.error("pass --check-plan or --ready")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    destination = json.loads(DESTINATION.read_text(encoding="utf-8"))
    errors = validate_plan(manifest, destination)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if args.ready:
        blockers = readiness_blockers(manifest)
        if blockers:
            print("\n".join(blockers), file=sys.stderr)
            return 2
        print("M11.8 publication preflight is ready")
        return 0
    print("M11.8 publication plan passes: 8 repositories, 5 explicit external blockers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
