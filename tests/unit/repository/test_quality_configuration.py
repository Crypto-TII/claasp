"""Regression tests for the pinned v5 quality-tool configuration."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file()
)


def _load_tool(name: str):
    tool_path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, tool_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ruff_version_scope_and_correctness_rules_are_pinned():
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "ruff==0.16.8" in configuration["project"]["optional-dependencies"]["quality"]
    ruff = configuration["tool"]["ruff"]
    assert ruff["target-version"] == "py311"
    selected = set(ruff["lint"]["select"])
    assert {"F", "I", "B006", "B023", "RUF009", "RUF012", "RUF100"} <= selected


def test_mypy_version_scope_and_regression_policy_are_pinned():
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "mypy==2.3.1" in configuration["project"]["optional-dependencies"]["quality"]
    mypy = configuration["tool"]["mypy"]
    assert mypy["files"] == ["src/claasp", "tests", "tools", "docs/conf.py"]
    assert mypy["warn_unused_ignores"] is True
    assert mypy["no_implicit_optional"] is True


def test_generated_primitive_exports_are_not_stale():
    generator = _load_tool("generate_primitive_exports")

    source, count = generator.render_exports()
    assert count == 142
    assert source == generator.DESTINATION.read_text(encoding="utf-8")


def test_typing_baseline_is_machine_readable_and_suppression_free():
    closure = _load_tool("typecheck_closure")
    baseline = json.loads(closure.BASELINE.read_text(encoding="utf-8"))

    assert not closure.suppression_violations()
    assert baseline["diagnostic_count"] == len(baseline["diagnostics"])
    assert baseline["inline_suppression_exceptions"] == []
    assert set(baseline["counts_by_scope"]) == set(closure.SCOPES)
    assert closure.validate_baseline(baseline, baseline) == ([], [])


def test_typing_baseline_rejects_new_stale_duplicate_and_wrong_scope_entries():
    closure = _load_tool("typecheck_closure")
    diagnostic = {
        "path": "src/claasp/example.py",
        "line": 1,
        "column": 1,
        "code": "assignment",
        "message": "fixture",
    }
    recorded = closure.build_baseline("mypy 2.3.1 (compiled: no)", [diagnostic])
    empty = closure.build_baseline("mypy 2.3.1 (compiled: no)", [])

    new, stale = closure.validate_baseline(empty, recorded)
    assert new == [diagnostic] and stale == []
    new, stale = closure.validate_baseline(recorded, empty)
    assert new == [] and stale == [diagnostic]
    duplicate = dict(recorded)
    duplicate["diagnostics"] = [diagnostic, diagnostic]
    duplicate["diagnostic_count"] = 2
    with pytest.raises(ValueError, match="duplicate diagnostics"):
        closure.validate_baseline(duplicate, recorded)
    wrong_scope = dict(recorded)
    wrong_scope["scope"] = ["src/claasp"]
    with pytest.raises(ValueError, match="stale checked scopes"):
        closure.validate_baseline(wrong_scope, recorded)


def test_typing_baseline_identity_is_stable_across_architecture_columns():
    closure = _load_tool("typecheck_closure")
    diagnostic = {
        "path": "src/claasp/example.py",
        "line": 1,
        "column": 1,
        "code": "assignment",
        "message": "fixture",
    }
    shifted = dict(diagnostic, column=19)
    recorded = closure.build_baseline("mypy 2.3.1 (compiled: yes)", [diagnostic])
    current = closure.build_baseline("mypy 2.3.1 (compiled: yes)", [shifted])

    assert closure.validate_baseline(recorded, current) == ([], [])
