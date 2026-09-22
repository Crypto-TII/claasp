"""Tests for the successor v5 review and release plan authority."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "review_release_plan_closure.py"
SPEC = importlib.util.spec_from_file_location("review_release_plan_closure", TOOL_PATH)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


def _authorities() -> tuple[dict[str, object], dict[str, object]]:
    plan = json.loads(closure.MANIFEST.read_text(encoding="utf-8"))
    destination = json.loads(closure.DESTINATION.read_text(encoding="utf-8"))
    return plan, destination


def test_committed_review_release_plan_passes():
    plan, destination = _authorities()
    assert closure.validate_plan(plan, destination) == []


def test_review_plan_rejects_merge_without_human_confirmation():
    plan, destination = _authorities()
    plan["merge_gate"] = {"human_confirmation": None, "status": "open"}

    assert any("human confirmation" in error for error in closure.validate_plan(plan, destination))


def test_review_plan_rejects_moving_satellite_migration_earlier():
    plan, destination = _authorities()
    phases = plan["phases"]
    assert isinstance(phases, list)
    phases[-2], phases[-3] = phases[-3], phases[-2]

    assert any("out of order" in error for error in closure.validate_plan(plan, destination))


def test_review_plan_rejects_license_drift():
    plan, destination = _authorities()
    license_record = plan["license"]
    assert isinstance(license_record, dict)
    license_record["selected_target"] = "Apache-2.0"

    assert any("MIT selection" in error for error in closure.validate_plan(plan, destination))


def test_review_plan_rejects_bit_vector_dependency_drift():
    plan, destination = _authorities()
    workstream = plan["bit_vector_workstream"]
    assert isinstance(workstream, dict)
    workstream["core_import_policy"] = "required-runtime-dependency"

    assert any(
        "bit-vector workstream" in error for error in closure.validate_plan(plan, destination)
    )
