"""Tests for the M10.16 wheel ownership gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path

TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "wheel_audit.py"
SPEC = importlib.util.spec_from_file_location("wheel_audit", TOOL_PATH)
assert SPEC and SPEC.loader
wheel_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wheel_audit)


def test_wheel_audit_accepts_owned_runtime_entries():
    entries = sorted(wheel_audit.REQUIRED | {"claasp_next/__init__.py"})

    assert wheel_audit.audit_entries(entries) == []


def test_wheel_audit_rejects_cache_baseline_config_and_native_artifacts():
    entries = sorted(
        wheel_audit.REQUIRED
        | {
            "claasp_next/__pycache__/module.pyc",
            "claasp_next/migration/m10_16_typing_baseline.json",
            "claasp_next/pyproject.toml",
            "claasp_next/generated.c",
            "claasp_next/native.so",
        }
    )

    violations = wheel_audit.audit_entries(entries)

    assert any("development-only path" in violation for violation in violations)
    assert any("development-only file" in violation for violation in violations)
    assert sum("native source" in violation for violation in violations) >= 3
