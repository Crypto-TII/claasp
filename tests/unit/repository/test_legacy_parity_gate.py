"""The current snapshot augments rather than rewrites frozen provenance."""

import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("legacy_parity_gate", "tools/legacy_parity_gate.py")
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def test_current_source_inventory_has_no_unmapped_added_modules():
    result = GATE.validate()
    assert result["core_inventory_files"] == 600
    assert result["delta_files"] == 19
    assert result["resources"] == 1667


def test_new_legacy_modules_fail_the_inventory_gate(tmp_path):
    data = tmp_path / "tools/data"
    data.mkdir(parents=True)
    original = json.loads(Path("tools/data/legacy_current_snapshot.json").read_text())
    original["python_files"].append({"path": "claasp/new_analysis.py", "sha256": "0" * 64})
    (data / "legacy_current_snapshot.json").write_text(json.dumps(original))
    # An empty baseline exposes the missing-module failure without relying on
    # implementation-specific fixture metadata.
    (data / "legacy_inventory.json").write_text('{"records": []}')
    with pytest.raises(ValueError, match="missing=.*new_analysis"):
        GATE.validate(root=tmp_path)
