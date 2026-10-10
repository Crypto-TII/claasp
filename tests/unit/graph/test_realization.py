import json
import subprocess
import sys
from pathlib import Path

import pytest

from claasp.domains import Bit
from claasp.graph import (
    AmbiguousRealizationError,
    ArrayType,
    Primitive,
    RealizationDescriptor,
    RealizationMaturity,
    UnsupportedRealizationError,
)

ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file()
)


def test_realization_audit_covers_every_packaged_multi_module_family():
    catalogue = json.loads((ROOT / "migration/realization_catalogue.json").read_text())
    audited = {
        item["canonical"].split(":", 1)[0].rsplit(".", 1)[0] for item in catalogue["families"]
    }
    primitive_root = ROOT / "src/claasp/primitives"
    packaged = set()
    for package in primitive_root.glob("*/*"):
        if not package.is_dir() or package.name == "__pycache__":
            continue
        implementation_modules = {
            path.stem
            for path in package.glob("*.py")
            if path.name not in {"__init__.py", "parameters.py"}
        }
        if len(implementation_modules) > 1:
            relative = package.relative_to(ROOT / "src")
            packaged.add(".".join(relative.parts))
    assert packaged <= audited


def test_realization_audit_has_unique_names_and_explicit_exclusions():
    catalogue = json.loads((ROOT / "migration/realization_catalogue.json").read_text())
    names = [item["family"] for item in catalogue["families"]]
    assert len(names) == len(set(names))
    for item in catalogue["families"]:
        assert item["equivalent"]
        assert len(item["equivalent"]) == len(set(item["equivalent"]))
        for exclusion in item["excluded"]:
            assert exclusion["module"] and exclusion["reason"]


class _SelectablePrimitive(Primitive):
    _realizations = (
        RealizationDescriptor(
            "reference",
            frozenset(("evaluate", "shared")),
            frozenset(("word",)),
            "reference graph",
            provenance=("unit fixture",),
            priority=0,
        ),
        RealizationDescriptor(
            "specialized",
            frozenset(("analyze", "shared")),
            frozenset(("sbox",)),
            "analysis graph",
            RealizationMaturity.EXPERIMENTAL,
            ("unit fixture",),
            10,
        ),
    )

    def __init__(self):
        super().__init__("selectable", {"value": ArrayType(Bit(), (1,))})
        self._builder.set_output(self.graph.input("value"))


_SelectablePrimitive._realization_builders = {
    "reference": _SelectablePrimitive,
    "specialized": _SelectablePrimitive,
}


def test_generic_explicit_and_capability_selection_are_deterministic():
    assert _SelectablePrimitive.realize("specialized").realization.name == "specialized"
    assert _SelectablePrimitive.for_capabilities({"analyze"}).realization.name == "specialized"
    assert _SelectablePrimitive.for_capabilities({"shared"}).realization.name == "reference"
    with pytest.raises(UnsupportedRealizationError, match="no _SelectablePrimitive realization"):
        _SelectablePrimitive.for_capabilities({"cuda"})
    with pytest.raises(AmbiguousRealizationError, match="unique policy"):
        _SelectablePrimitive.for_capabilities({"shared"}, policy="unique")


def test_realization_metadata_and_default_identity_are_stable():
    primitive = Primitive("plain", {"value": ArrayType(Bit(), (1,))})
    assert primitive.realization_identity == "plain:default"
    descriptor = _SelectablePrimitive.available_realizations()[1]
    assert descriptor.structure == frozenset(("sbox",))
    assert descriptor.maturity is RealizationMaturity.EXPERIMENTAL
    assert descriptor.provenance == ("unit fixture",)


def test_realization_representation_is_readable_in_an_interactive_shell():
    descriptor = _SelectablePrimitive.available_realizations()[1]
    assert repr(descriptor) == (
        "Realization: specialized\n"
        "  Description: analysis graph\n"
        "  Maturity: experimental\n"
        "  Capabilities: analyze, shared\n"
        "  Graph structure: sbox\n"
        "  Provenance: unit fixture"
    )


def test_realization_closure_gate_passes():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools/realization_closure.py"), "--check"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "16 interchangeable families, 36 graphs" in completed.stdout
