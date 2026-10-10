#!/usr/bin/env python3
"""Validate the post-implementation v5 review and release plan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "migration" / "v5_review_release_plan.json"
DESTINATION = ROOT / "migration" / "m11_repository_destination.json"
MATRIX = ROOT / "migration" / "m11a_bidirectional_migration.json"


def validate_plan(plan: dict[str, Any], destination: dict[str, Any]) -> list[str]:
    """Return deterministic violations in the successor-plan authority."""

    errors: list[str] = []
    if plan.get("schema_version") != 1 or plan.get("status") != "active":
        errors.append("review plan identity or status is invalid")
    authority = plan.get("authority")
    if (
        authority != "docs/architecture/v5-review-and-release-plan.md"
        or not (ROOT / authority).is_file()
    ):
        errors.append("review plan document is missing")

    predecessor = plan.get("predecessor_plan")
    if predecessor != {
        "path": "docs/architecture/v5-plan.md",
        "status": "closed-implementation-baseline",
    }:
        errors.append("predecessor implementation plan is not closed")
    else:
        text = (ROOT / predecessor["path"]).read_text(encoding="utf-8")
        if "Status: closed implementation baseline" not in text:
            errors.append("predecessor plan lacks its closed status marker")

    repositories = destination.get("affiliated_repository_candidates", [])
    expected_scope = sorted(row["source_full_name"] for row in repositories)
    if plan.get("initial_repository_scope") != expected_scope:
        errors.append("review plan repository scope differs from destination authority")
    if plan.get("excluded_from_initial_scope") != destination.get("excluded_from_initial_scope"):
        errors.append("review plan exclusions differ from destination authority")

    phases = plan.get("phases")
    if not isinstance(phases, list) or [row.get("id") for row in phases] != [
        f"R{number}" for number in range(1, 11)
    ]:
        errors.append("review phases are missing or out of order")
    elif (
        phases[0].get("status") != "achieved"
        or phases[1].get("status") != "pending-human-review"
        or phases[-2].get("name") != "final-satellite-repository-migration"
        or phases[-1].get("status") != "deferred-final-step"
    ):
        errors.append("review, final migration, or publication ordering is stale")

    merge = plan.get("merge_gate")
    if merge != {"human_confirmation": None, "status": "closed-pending-human-review"}:
        errors.append("merge gate opened without human confirmation")
    license_record = plan.get("license")
    if license_record != {
        "application_phase": "R7",
        "current": "GPL-3.0-or-later",
        "selected_target": "MIT",
        "selected_at": "2026-09-21",
    }:
        errors.append("MIT selection or application phase is stale")

    if plan.get("bit_vector_workstream") != {
        "canonical_image_dependency": "Boolector",
        "core_import_policy": "optional-driver-only",
        "implementation_session": "dedicated-follow-up",
        "license_and_provenance_review_required": True,
        "reference_implementations": ["ranea/CASCADA", "CryptoSMT"],
    }:
        errors.append("bit-vector workstream scope or isolation policy is stale")

    materials = plan.get("required_review_material")
    if not isinstance(materials, list) or materials != sorted(set(materials)):
        errors.append("review material paths must be unique and sorted")
    else:
        for relative in materials:
            if not (ROOT / relative).is_file():
                errors.append(f"required review material is missing: {relative}")
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    if matrix.get("summary") != {
        "legacy_by_disposition": {
            "inapplicable": 34,
            "migrate": 332,
            "remove": 8,
            "supersede": 207,
        },
        "legacy_records": 581,
        "v5_artifacts": 416,
        "v5_by_classification": {"legacy-lineage": 377, "new-v5": 39},
    }:
        errors.append("review matrix counts are stale")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("pass --check")
    plan = json.loads(MANIFEST.read_text(encoding="utf-8"))
    destination = json.loads(DESTINATION.read_text(encoding="utf-8"))
    errors = validate_plan(plan, destination)
    if errors:
        print("\n".join(errors))
        return 1
    print("v5 review/release plan passes: R1 achieved, R2 human review is the next gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
