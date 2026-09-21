"""Validate the M11 repository destination and preservation authority."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "migration" / "m11_repository_destination.json"
EXPECTED_REPOSITORIES = {
    "Crypto-TII/claasp",
    "Crypto-TII/claasping_aradi",
    "Crypto-TII/claasping_ballet",
    "Crypto-TII/claasping_splight",
    "peacker/claasp_solvers_benchmarks",
}
EXPECTED_EXCLUSIONS = [
    "claasp-llm",
    "claasp-pro",
    "claasp-symmetric-cipher-analysis",
    "jupyter-claasp-cascada-deployment",
]


def validate_manifest(manifest: dict[str, object]) -> list[str]:
    """Return deterministic violations in one destination manifest."""

    errors: list[str] = []
    if manifest.get("schema_version") != 1 or manifest.get("milestone") != "M11.1":
        errors.append("manifest identity or schema is invalid")

    source = manifest.get("source_repository")
    if not isinstance(source, dict):
        errors.append("source repository record is missing")
    else:
        if source.get("full_name") != "Crypto-TII/claasp":
            errors.append("source repository identity is stale")
        if source.get("visibility") != "public":
            errors.append("the star-bearing source repository must remain public")
        for field in ("stars", "forks", "releases", "subscribers"):
            if not isinstance(source.get(field), int) or source[field] < 0:
                errors.append(f"source {field} count is invalid")

    destination = manifest.get("destination")
    if not isinstance(destination, dict):
        errors.append("destination record is missing")
    else:
        if destination.get("preferred_handle") != "claasp":
            errors.append("preferred organization handle is stale")
        status = destination.get("preferred_handle_status")
        if status not in {"blocked-by-existing-personal-account", "available", "created"}:
            errors.append("preferred handle status is invalid")
        accepted = destination.get("accepted_handle")
        if status in {"available", "created"} and accepted != "claasp":
            errors.append("an available or created preferred handle must be accepted")
        if status == "blocked-by-existing-personal-account" and accepted is not None:
            errors.append("a blocked preferred handle cannot be accepted")
        if destination.get("staging_repository_name") == "claasp":
            errors.append("private staging must not occupy the final transfer name")
        if destination.get("minimum_owners", 0) < 2:
            errors.append("destination organization requires at least two owners")

    invariants = manifest.get("launch_invariants")
    expected_invariants = {
        "change_source_visibility": False,
        "create_staging_at_final_name": False,
        "install_v5_only_after_validation": True,
        "preserve_v4_branch_or_tag": True,
        "transfer_existing_repository": True,
    }
    if invariants != expected_invariants:
        errors.append("launch preservation invariants are incomplete or unsafe")

    repositories = manifest.get("affiliated_repository_candidates")
    if not isinstance(repositories, list) or not repositories:
        errors.append("affiliated repository inventory is missing")
    else:
        names = [
            item["name"]
            for item in repositories
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ]
        if len(names) != len(repositories) or names != sorted(set(names)):
            errors.append("affiliated repository names must be complete, unique, and sorted")
        full_names = {
            item.get("source_full_name") for item in repositories if isinstance(item, dict)
        }
        if full_names != EXPECTED_REPOSITORIES:
            errors.append("initial repository scope differs from the confirmed authority")
        for item in repositories:
            if not isinstance(item, dict):
                continue
            if item.get("name") == "claasp":
                if item.get("target_visibility_before_launch") != "public":
                    errors.append("the star-bearing repository must remain public before launch")
            elif item.get("target_visibility_before_launch") != "private":
                errors.append(f"staged affiliated repository is not private: {item.get('name')!r}")
            if item.get("name") != "claasp" and (
                item.get("compatibility_baseline") != "legacy-claasp"
                or item.get("migration_timing") != "final-migration-phase"
            ):
                errors.append(f"satellite migration timing is stale: {item.get('name')!r}")

    if manifest.get("excluded_from_initial_scope") != EXPECTED_EXCLUSIONS:
        errors.append("out-of-scope repository record is stale")
    if manifest.get("initial_scope_confirmed_at") != "2026-09-21":
        errors.append("initial repository scope lacks confirmation evidence")

    requirements = manifest.get("open_requirements")
    if not isinstance(requirements, list) or len(requirements) != 2:
        errors.append("external destination requirements are incomplete")
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
    source = manifest["source_repository"]
    destination = manifest["destination"]
    print(
        "M11 destination authority passes: "
        f"{source['stars']} stars and {source['forks']} forks protected; "
        f"preferred handle {destination['preferred_handle_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
