#!/usr/bin/env python3
"""Enumerate and validate the complete exported CLAASP v5 Python API.

The tool uses the runtime value of every statically declared ``__all__`` so
lazy and catalogue-generated exports are included. Run it from ``next/`` with
``PYTHONPATH=src python tools/public_api_closure.py --check``.
"""

from __future__ import annotations

import argparse
import ast
from collections import defaultdict
import dataclasses
import enum
import importlib
import inspect
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "next" / "src" / "claasp_next"
AUTHORITY = ROOT / "next" / "migration" / "m10_16_public_api.json"
SCHEMA_VERSION = 1
SECTION_ORDER = (
    "Parameters",
    "Returns",
    "Raises",
    "Applicability",
    "Provenance",
    "Side effects",
    "Optional dependencies",
    "EXAMPLES::",
)
EXCEPTION_CATEGORIES = {
    "abstract_protocol",
    "external_executable",
    "unsafe_execution_boundary",
    "environment_owned_interaction",
}


def _declares_all(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
                return True
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "__all__":
                return True
    return False


def public_modules(source_root: Path = SOURCE_ROOT) -> tuple[str, ...]:
    """Return modules which explicitly declare a public export list."""

    modules = []
    for path in sorted(source_root.rglob("*.py")):
        if not _declares_all(path):
            continue
        parts = list(path.relative_to(source_root.parent).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        modules.append(".".join(parts))
    return tuple(modules)


def _canonical_name(value: Any, fallback: str) -> str:
    module = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    if isinstance(module, str) and isinstance(qualname, str):
        return f"{module}.{qualname}"
    return fallback


def _export_kind(value: Any) -> str:
    if inspect.isclass(value):
        if issubclass(value, enum.Enum):
            return "enum"
        if dataclasses.is_dataclass(value):
            return "dataclass"
        if inspect.isabstract(value):
            return "abstract_class"
        return "class"
    if inspect.isroutine(value):
        return "function"
    return "data"


def _member_value(value: Any) -> Any:
    if isinstance(value, property):
        return value.fget
    if isinstance(value, (classmethod, staticmethod)):
        return value.__func__
    return value


def _member_kind(name: str, value: Any) -> str | None:
    if name == "__init__":
        return "constructor"
    if isinstance(value, property):
        return "property"
    if inspect.isfunction(value) or isinstance(value, (classmethod, staticmethod)):
        return "method"
    return None


def enumerate_public_api(source_root: Path = SOURCE_ROOT) -> list[dict[str, Any]]:
    """Return deterministic module, export, member, field, and enum records."""

    modules = public_modules(source_root)
    entries: dict[str, dict[str, Any]] = {}
    exported_classes: dict[int, type[Any]] = {}

    for module_name in modules:
        module = importlib.import_module(module_name)
        entries[module_name] = {
            "qualified_name": module_name,
            "kind": "module",
            "canonical_name": module_name,
            "defined_in": module_name,
        }
        names = getattr(module, "__all__", None)
        if not isinstance(names, (list, tuple)) or not all(isinstance(name, str) for name in names):
            raise ValueError(f"{module_name}.__all__ must be a list or tuple of strings")
        if len(names) != len(set(names)):
            raise ValueError(f"{module_name}.__all__ contains duplicate names")
        for name in names:
            qualified_name = f"{module_name}.{name}"
            try:
                value = getattr(module, name)
            except (AttributeError, ImportError) as error:
                raise ValueError(f"public export does not resolve: {qualified_name}: {error}") from error
            canonical = _canonical_name(value, qualified_name)
            entries[qualified_name] = {
                "qualified_name": qualified_name,
                "kind": _export_kind(value),
                "canonical_name": canonical,
                "defined_in": getattr(value, "__module__", module_name),
            }
            if inspect.isclass(value):
                exported_classes[id(value)] = value

    inherited_by: dict[str, set[str]] = defaultdict(set)
    member_records: dict[str, dict[str, Any]] = {}
    for exported_class in exported_classes.values():
        exported_canonical = _canonical_name(exported_class, exported_class.__name__)
        constructor_name = f"{exported_canonical}.__init__"
        member_records.setdefault(
            constructor_name,
            {
                "qualified_name": constructor_name,
                "kind": "constructor",
                "canonical_name": constructor_name,
                "defined_in": exported_class.__module__,
                "documented_by": exported_canonical,
            },
        )
        for defining_class in exported_class.__mro__:
            if defining_class is object or not defining_class.__module__.startswith("claasp_next"):
                continue
            if defining_class is not exported_class and id(defining_class) not in exported_classes:
                continue
            class_canonical = _canonical_name(defining_class, defining_class.__name__)
            for name, value in vars(defining_class).items():
                if name.startswith("_") and name != "__init__":
                    continue
                kind = _member_kind(name, value)
                if kind is None:
                    continue
                if kind == "constructor":
                    continue
                qualified_name = f"{class_canonical}.{name}"
                member_records.setdefault(
                    qualified_name,
                    {
                        "qualified_name": qualified_name,
                        "kind": kind,
                        "canonical_name": qualified_name,
                        "defined_in": defining_class.__module__,
                    },
                )
                if defining_class is not exported_class:
                    inherited_by[qualified_name].add(exported_canonical)

        if dataclasses.is_dataclass(exported_class):
            for field in dataclasses.fields(exported_class):
                qualified_name = f"{exported_canonical}.{field.name}"
                entries.setdefault(
                    qualified_name,
                    {
                        "qualified_name": qualified_name,
                        "kind": "dataclass_field",
                        "canonical_name": qualified_name,
                        "defined_in": exported_class.__module__,
                        "documented_by": exported_canonical,
                    },
                )
        if issubclass(exported_class, enum.Enum):
            for name in exported_class.__members__:
                qualified_name = f"{exported_canonical}.{name}"
                entries.setdefault(
                    qualified_name,
                    {
                        "qualified_name": qualified_name,
                        "kind": "enum_member",
                        "canonical_name": qualified_name,
                        "defined_in": exported_class.__module__,
                        "documented_by": exported_canonical,
                    },
                )

    for qualified_name, record in member_records.items():
        if inherited_by[qualified_name]:
            record["inherited_by"] = sorted(inherited_by[qualified_name])
        entries.setdefault(qualified_name, record)
    return [entries[name] for name in sorted(entries)]


def _resolve(qualified_name: str) -> Any:
    parts = qualified_name.split(".")
    for boundary in range(len(parts), 0, -1):
        try:
            value: Any = importlib.import_module(".".join(parts[:boundary]))
        except ImportError:
            continue
        for part in parts[boundary:]:
            value = inspect.getattr_static(value, part)
        return _member_value(value)
    raise LookupError(qualified_name)


def validate_docstring(docstring: str | None, qualified_name: str) -> list[str]:
    """Return structural violations for one public docstring."""

    violations = []
    if not docstring:
        return [f"{qualified_name}: missing docstring"]
    clean = inspect.cleandoc(docstring)
    summary = clean.splitlines()[0].strip()
    if len(summary.split()) < 4:
        violations.append(f"{qualified_name}: summary is too short")
    if "sage:" in clean:
        violations.append(f"{qualified_name}: Sage prompt is forbidden")
    positions = []
    for section in SECTION_ORDER:
        match = re.search(rf"(?m)^\s*{re.escape(section)}\s*$", clean)
        if match:
            positions.append((match.start(), SECTION_ORDER.index(section), section))
    ordered_indices = [item[1] for item in sorted(positions)]
    if ordered_indices != sorted(ordered_indices):
        violations.append(f"{qualified_name}: docstring sections are out of order")
    if re.search(r"(?m)^\s*(Args|Arguments|Example|Examples):\s*$", clean):
        violations.append(f"{qualified_name}: use the canonical section names")
    if "EXAMPLES::" in clean and ">>>" not in clean:
        violations.append(f"{qualified_name}: EXAMPLES:: has no Python prompt")
    return violations


def _example_required(entry: dict[str, Any]) -> bool:
    return entry["kind"] in {
        "abstract_class",
        "class",
        "constructor",
        "dataclass",
        "enum",
        "function",
        "method",
    }


def _has_example(docstring: str | None) -> bool:
    return bool(docstring and "EXAMPLES::" in docstring and ">>>" in docstring)


def _scoped_example(entry: dict[str, Any], docstring: str | None) -> bool:
    if _has_example(docstring):
        return True
    if entry["kind"] != "method":
        return False
    owner_name = entry["canonical_name"].rsplit(".", 1)[0]
    try:
        owner_doc = inspect.getdoc(_resolve(owner_name))
    except (AttributeError, ImportError, LookupError):
        return False
    return _has_example(owner_doc)


def load_authority(path: Path = AUTHORITY) -> dict[str, Any]:
    """Load the committed M10.16 public-API authority."""

    return json.loads(path.read_text(encoding="utf-8"))


def validate_authority(authority: dict[str, Any], entries: list[dict[str, Any]]) -> list[str]:
    """Return stale-entry and exception-schema violations."""

    violations = []
    if authority.get("schema_version") != SCHEMA_VERSION:
        violations.append("authority: unsupported schema_version")
    recorded = authority.get("entries")
    recorded_sequence = recorded if isinstance(recorded, list) else []
    recorded_qualified_names = [
        entry.get("qualified_name") for entry in recorded_sequence if isinstance(entry, dict)
    ]
    if len(recorded_qualified_names) != len(set(recorded_qualified_names)):
        violations.append("authority: duplicate public API identities")
    if recorded != entries:
        live_names = {entry["qualified_name"] for entry in entries}
        recorded_names = set(recorded_qualified_names)
        for name in sorted(live_names - recorded_names):
            violations.append(f"authority: unregistered public API {name}")
        for name in sorted(recorded_names - live_names):
            violations.append(f"authority: stale public API {name}")
        if live_names == recorded_names:
            violations.append("authority: public API metadata is stale")
    entry_names = {entry["qualified_name"] for entry in entries}
    exceptions = authority.get("example_exceptions", [])
    seen = set()
    for exception in exceptions:
        name = exception.get("qualified_name")
        if name in seen:
            violations.append(f"authority: duplicate exception {name}")
        seen.add(name)
        if name not in entry_names:
            violations.append(f"authority: stale exception {name}")
        if exception.get("category") not in EXCEPTION_CATEGORIES:
            violations.append(f"authority: invalid exception category for {name}")
        for field in ("reason", "owner", "evidence"):
            if not isinstance(exception.get(field), str) or not exception[field].strip():
                violations.append(f"authority: exception {name} lacks {field}")
        evidence = exception.get("evidence")
        if isinstance(evidence, str) and evidence.strip():
            evidence_path = ROOT / evidence.split("::", 1)[0]
            if not evidence_path.exists():
                violations.append(f"authority: exception {name} has missing evidence {evidence}")
        try:
            value = _resolve(name)
        except (AttributeError, ImportError, LookupError):
            continue
        if _has_example(inspect.getdoc(value)):
            violations.append(f"authority: exception {name} already has an example")
    return violations


def documentation_violations(
    entries: Iterable[dict[str, Any]], authority: dict[str, Any]
) -> list[str]:
    """Return all live documentation and executable-example violations."""

    violations = []
    exceptions = {
        item["qualified_name"] for item in authority.get("example_exceptions", [])
    }
    checked_canonical_docs = set()
    for entry in entries:
        if entry["kind"] in {"data", "dataclass_field", "enum_member"}:
            continue
        doc_owner = entry["canonical_name"]
        if entry["kind"] == "constructor":
            doc_owner = entry["canonical_name"].removesuffix(".__init__")
        if doc_owner in checked_canonical_docs:
            continue
        checked_canonical_docs.add(doc_owner)
        try:
            value = _resolve(doc_owner)
        except (AttributeError, ImportError, LookupError) as error:
            violations.append(f"{doc_owner}: cannot resolve documentation owner: {error}")
            continue
        docstring = inspect.getdoc(value)
        violations.extend(validate_docstring(docstring, doc_owner))
        if _example_required(entry) and doc_owner not in exceptions and not _scoped_example(entry, docstring):
            violations.append(f"{doc_owner}: missing executable EXAMPLES:: section")
    return sorted(set(violations))


def build_authority(entries: list[dict[str, Any]], previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the deterministic authority while retaining reviewed exceptions."""

    return {
        "schema_version": SCHEMA_VERSION,
        "public_api_rule": "runtime __all__ exports plus canonical public class members",
        "entries": entries,
        "example_exceptions": [] if previous is None else previous.get("example_exceptions", []),
    }


def main(argv: list[str] | None = None) -> int:
    """Write, inspect, or fully validate the public-API authority."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="rewrite the committed authority")
    parser.add_argument("--check-authority", action="store_true", help="check enumeration and exceptions")
    parser.add_argument("--check", action="store_true", help="check authority and documentation closure")
    parser.add_argument("--report", action="store_true", help="print documentation violation counts")
    args = parser.parse_args(argv)

    entries = enumerate_public_api()
    previous = load_authority() if AUTHORITY.exists() else None
    if args.write:
        authority = build_authority(entries, previous)
        AUTHORITY.write_text(json.dumps(authority, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {len(entries)} public API entries to {AUTHORITY.relative_to(ROOT)}")
        return 0
    if previous is None:
        print(f"missing authority: {AUTHORITY.relative_to(ROOT)}", file=sys.stderr)
        return 1
    violations = validate_authority(previous, entries)
    doc_violations = documentation_violations(entries, previous)
    if args.report:
        print(f"public API entries: {len(entries)}")
        print(f"authority violations: {len(violations)}")
        print(f"documentation violations: {len(doc_violations)}")
    if args.check:
        violations.extend(doc_violations)
    if violations:
        for violation in violations:
            print(violation, file=sys.stderr)
        return 1
    if args.check or args.check_authority:
        print(f"public API authority passes: {len(entries)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
