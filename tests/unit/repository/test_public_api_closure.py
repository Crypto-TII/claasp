"""Tests for the M10.16 public-API documentation authority."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path

TOOL_PATH = (
    next(
        parent
        for parent in Path(__file__).resolve().parents
        if (parent / "pyproject.toml").is_file()
    )
    / "tools"
    / "public_api_closure.py"
)
SPEC = importlib.util.spec_from_file_location("public_api_closure", TOOL_PATH)
assert SPEC and SPEC.loader
public_api_closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_api_closure)


def test_committed_public_api_authority_is_complete_and_deterministic():
    entries = public_api_closure.enumerate_public_api()
    authority = public_api_closure.load_authority()

    assert entries == sorted(entries, key=lambda entry: entry["qualified_name"])
    assert not public_api_closure.validate_authority(authority, entries)
    assert {entry["kind"] for entry in entries} >= {
        "module",
        "class",
        "constructor",
        "method",
        "property",
        "dataclass",
        "dataclass_field",
        "enum",
        "enum_member",
    }
    assert any(entry.get("inherited_by") for entry in entries)
    assert any(
        entry["qualified_name"] == "claasp.primitives.AES"
        and entry["canonical_name"] != entry["qualified_name"]
        for entry in entries
    )

    class AbstractFixture(ABC):
        @abstractmethod
        def execute(self):
            """Execute the fixture contract."""

    assert public_api_closure._export_kind(AbstractFixture) == "abstract_class"


def test_docstring_validator_rejects_missing_trivial_malformed_and_sage_examples():
    validate = public_api_closure.validate_docstring

    assert validate(None, "fixture.missing") == ["fixture.missing: missing docstring"]
    assert "summary is too short" in validate("Tiny summary.", "fixture.trivial")[0]
    malformed = """Describe deterministic behavior for callers.

    Returns
    -------
    int

    Parameters
    ----------
    value : int

    EXAMPLES::

        sage: example(1)
    """
    violations = validate(malformed, "fixture.malformed")
    assert any("out of order" in violation for violation in violations)
    assert any("Sage prompt" in violation for violation in violations)
    assert any("no Python prompt" in violation for violation in violations)


def test_authority_rejects_unregistered_stale_and_duplicate_entries():
    entries = [
        {
            "qualified_name": "fixture.current",
            "kind": "module",
            "canonical_name": "fixture.current",
            "defined_in": "fixture.current",
        }
    ]
    authority = {
        "schema_version": public_api_closure.SCHEMA_VERSION,
        "entries": [
            {
                "qualified_name": "fixture.stale",
                "kind": "module",
                "canonical_name": "fixture.stale",
                "defined_in": "fixture.stale",
            },
            {
                "qualified_name": "fixture.stale",
                "kind": "module",
                "canonical_name": "fixture.stale",
                "defined_in": "fixture.stale",
            },
        ],
        "example_exceptions": [
            {
                "qualified_name": "fixture.stale",
                "category": "too_difficult",
                "reason": "",
                "owner": "",
                "evidence": "",
            },
            {
                "qualified_name": "fixture.stale",
                "category": "abstract_protocol",
                "reason": "abstract",
                "owner": "M10.16",
                "evidence": "tests/fixture.py",
            },
        ],
    }

    violations = public_api_closure.validate_authority(authority, entries)
    assert any("unregistered public API" in violation for violation in violations)
    assert any("stale public API" in violation for violation in violations)
    assert any("duplicate exception" in violation for violation in violations)
    assert any("duplicate public API identities" in violation for violation in violations)
    assert any("invalid exception category" in violation for violation in violations)
    assert any("lacks reason" in violation for violation in violations)
    assert any("missing evidence" in violation for violation in violations)


def test_private_helpers_do_not_become_public_by_filename():
    modules = public_api_closure.public_modules()

    assert "claasp.primitives._realizations" not in modules
    assert "claasp.components.word._validation" not in modules
    assert "claasp.primitives._catalogue_exports" in modules
    assert "claasp.primitives" in modules


def test_foundational_public_api_documentation_is_closed():
    """Keep the M10.16c graph-authoring and semantic boundary closed."""

    prefixes = (
        "claasp.annotations",
        "claasp.components",
        "claasp.domains",
        "claasp.encoding",
        "claasp.graph",
        "claasp.provenance",
        "claasp.semantics",
        "claasp.utils",
    )
    entries = public_api_closure.enumerate_public_api()
    authority = public_api_closure.load_authority()
    violations = public_api_closure.documentation_violations(entries, authority)

    assert not [violation for violation in violations if violation.startswith(prefixes)]


def test_processing_public_api_documentation_is_closed():
    """Keep the M10.16d representation and result-processing boundary closed."""

    prefixes = (
        "claasp.analysis",
        "claasp.catalogue",
        "claasp.composites",
        "claasp.drivers",
        "claasp.presentation",
        "claasp.representations",
        "claasp.serialization",
        "claasp.transformations",
    )
    entries = public_api_closure.enumerate_public_api()
    authority = public_api_closure.load_authority()
    violations = public_api_closure.documentation_violations(entries, authority)

    assert not [violation for violation in violations if violation.startswith(prefixes)]


def test_primitive_catalogue_public_api_documentation_is_closed():
    """Keep every generated and hand-authored primitive export documented."""

    entries = public_api_closure.enumerate_public_api()
    authority = public_api_closure.load_authority()
    violations = public_api_closure.documentation_violations(entries, authority)

    assert not [violation for violation in violations if violation.startswith("claasp.primitives")]


def test_complete_public_api_audit_does_not_import_optional_packages():
    code = """
import importlib.util
import sys
from pathlib import Path
path = Path('tools/public_api_closure.py')
spec = importlib.util.spec_from_file_location('public_api_closure', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
before = set(sys.modules)
module.enumerate_public_api()
forbidden = {'matplotlib', 'minizinc', 'numpy', 'pandas', 'sage', 'sklearn', 'z3'}
print(','.join(sorted(forbidden & {name.split('.')[0] for name in set(sys.modules) - before})))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=TOOL_PATH.parents[1],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == ""
