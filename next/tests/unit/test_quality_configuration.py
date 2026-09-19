"""Regression tests for the pinned v5 quality-tool configuration."""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ruff_version_scope_and_correctness_rules_are_pinned():
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "ruff==0.16.8" in configuration["project"]["optional-dependencies"]["quality"]
    ruff = configuration["tool"]["ruff"]
    assert ruff["target-version"] == "py311"
    selected = set(ruff["lint"]["select"])
    assert {"F", "I", "B006", "B023", "RUF009", "RUF012", "RUF100"} <= selected


def test_generated_primitive_exports_are_not_stale():
    tool_path = ROOT / "tools" / "generate_primitive_exports.py"
    spec = importlib.util.spec_from_file_location("generate_primitive_exports", tool_path)
    assert spec and spec.loader
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)

    source, count = generator.render_exports()
    assert count == 142
    assert source == generator.DESTINATION.read_text(encoding="utf-8")
