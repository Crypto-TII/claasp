"""Discover implementation-owned declarations for every catalogue section.

Only the build/check pipeline imports owners. Runtime catalogue queries read the
committed JSON and do not walk packages or load optional solver implementations.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from dataclasses import dataclass
from pathlib import Path

from claasp._catalogue_metadata import _Entry

ROOT = Path(__file__).parents[1]
PACKAGE = ROOT / "src/claasp"


@dataclass(frozen=True)
class DiscoveredEntry:
    owner: str
    declaration: _Entry

    @property
    def name(self):
        return self.declaration.metadata.get("name", self.declaration.implementation.__name__)

    @property
    def implementation(self):
        value = self.declaration.implementation
        binding = self.name if self.declaration.category == "primitive" else value.__qualname__
        return f"{self.owner}:{binding}"


def declared_modules(package=PACKAGE):
    """Find module declarations statically, without importing unrelated modules."""
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(target, ast.Name) and target.id == "__catalogue__"
                for target in (node.targets if isinstance(node, ast.Assign) else (node.target,))
            )
            for node in tree.body
        ):
            parts = path.relative_to(package.parent).with_suffix("").parts
            yield ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def discover(modules=None):
    """Collect declarations, rejecting duplicate identities and stale bindings."""
    result = []
    identities = set()
    for module_name in declared_modules() if modules is None else sorted(modules):
        module = importlib.import_module(module_name)
        entries = module.__catalogue__
        if not isinstance(entries, tuple):
            raise TypeError(f"{module_name}.__catalogue__ must be a tuple")
        for declaration in entries:
            if not isinstance(declaration, _Entry):
                raise TypeError(f"invalid catalogue declaration in {module_name}")
            row = DiscoveredEntry(module_name, declaration)
            identity = (declaration.category, row.name)
            if identity in identities:
                raise ValueError(f"duplicate catalogue identity: {identity}")
            identities.add(identity)
            value = module
            for part in row.implementation.split(":", 1)[1].split("."):
                value = getattr(value, part)
            if value is not declaration.implementation:
                raise ValueError(f"stale catalogue binding: {row.implementation}")
            result.append(row)
    return tuple(sorted(result, key=lambda row: (row.declaration.category, row.name)))


def primitive_exports(entries=None):
    """Derive public primitive imports from their implementation-owned bindings."""
    entries = discover() if entries is None else entries
    return tuple(
        (row.owner.split(".")[2], row.name, row.owner)
        for row in entries
        if row.declaration.category == "primitive"
    )


def driver_records(entries):
    rows = []
    for row in entries:
        entry = row.declaration
        if entry.category != "driver":
            continue
        metadata = dict(entry.metadata)
        metadata.pop("name", None)
        parameter = metadata.pop("target_parameter", None)
        if parameter is not None:
            parameters = inspect.signature(entry.implementation).parameters
            if parameter not in parameters:
                raise ValueError(f"{row.name}: unknown dependency parameter {parameter!r}")
            default = parameters[parameter].default
            if not isinstance(default, str) or not default:
                raise ValueError(f"{row.name}: dependency parameter needs a string default")
            metadata["target"] = default
        availability = metadata["availability"]
        if availability == "builtin":
            metadata["target"] = None
        elif not metadata.get("target"):
            raise ValueError(f"{row.name}: missing dependency target")
        if availability == "minizinc_solver":
            executable = inspect.signature(entry.implementation).parameters["executable"].default
            metadata["target"] = f"{executable}:{metadata['target']}"
        rows.append(dict(name=row.name, implementation=row.implementation, **metadata))
    return rows


def analysis_records(entries):
    """Include public facade methods without inventing compatibility guarantees."""
    rows = {}
    for row in entries:
        entry = row.declaration
        if entry.category == "analysis_api":
            for name, _function in inspect.getmembers(entry.implementation, inspect.isfunction):
                if name.startswith("_"):
                    continue
                rows[name] = dict(
                    name=name,
                    entry_point=f"Primitive.analysis.{name}",
                    kind="analysis",
                    evidence="unspecified",
                    representations=[],
                    drivers=[],
                    required_components=[],
                    primitives=[],
                    restriction="See the method documentation for parameter and backend applicability; catalogue compatibility is not declared.",
                )
    for row in entries:
        entry = row.declaration
        if entry.category != "analysis":
            continue
        metadata = dict(entry.metadata)
        metadata.pop("name", None)
        facade = entry.implementation.__qualname__.startswith("Analysis.")
        entry_point = (
            f"Primitive.analysis.{entry.implementation.__name__}"
            if facade
            else row.implementation.replace(":", ".")
        )
        rows[row.name] = dict(name=row.name, entry_point=entry_point, **metadata)
    return [rows[name] for name in sorted(rows)]


def component_records(entries):
    """Discover actual component types; link teaching wrappers where available."""
    import claasp.components as public
    from claasp.graph import Component

    wrappers = {
        row.name: row.owner
        for row in entries
        if row.declaration.category == "primitive"
        and row.owner.split(".")[2] == "single_component_primitives"
    }
    return [
        dict(
            name=name, module=value.__module__, primitive_wrapper=name if name in wrappers else None
        )
        for name in sorted(public.__all__)
        if inspect.isclass(value := getattr(public, name))
        and issubclass(value, Component)
        and value is not Component
    ]


def representation_records(entries):
    return [
        dict(
            name=row.name,
            implementation=row.implementation,
            **{key: value for key, value in row.declaration.metadata.items() if key != "name"},
        )
        for row in entries
        if row.declaration.category == "representation"
    ]


def validate_public_api(entries):
    """Reject public primitive/driver implementations missing a declaration."""
    import claasp.primitives as public
    from claasp.graph import Primitive

    primitives = {
        row.declaration.implementation for row in entries if row.declaration.category == "primitive"
    }
    if any(not inspect.isclass(value) or not issubclass(value, Primitive) for value in primitives):
        raise ValueError("primitive declarations must reference Primitive classes")
    modules = [public] + [
        importlib.import_module("claasp.primitives." + category)
        for category in sorted({category for category, _, _ in primitive_exports(entries)})
    ]
    for module in modules:
        for name in module.__all__:
            value = getattr(module, name)
            if inspect.isclass(value) and issubclass(value, Primitive) and value not in primitives:
                raise ValueError(
                    f"public primitive lacks catalogue declaration: {module.__name__}.{name}"
                )
    drivers = {
        row.declaration.implementation for row in entries if row.declaration.category == "driver"
    }
    from claasp.drivers.base import Driver, SolverDriver

    for path in sorted((PACKAGE / "primitives").rglob("*.py")):
        if any(
            part.startswith("_") and part != "__init__.py"
            for part in path.relative_to(PACKAGE).parts
        ):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or node.name.startswith("_"):
                continue
            parts = path.relative_to(PACKAGE.parent).with_suffix("").parts
            module = importlib.import_module(
                ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
            )
            value = getattr(module, node.name)
            if issubclass(value, Primitive) and value not in primitives:
                raise ValueError(
                    f"primitive lacks catalogue declaration: {module.__name__}.{node.name}"
                )
    for path in sorted((PACKAGE / "drivers").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or node.name.startswith("_"):
                continue
            parts = path.relative_to(PACKAGE.parent).with_suffix("").parts
            module = importlib.import_module(
                ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
            )
            value = getattr(module, node.name)
            if (
                (
                    issubclass(value, (Driver, SolverDriver))
                    or node.name.endswith(("Driver", "Solver"))
                )
                and not getattr(value, "_is_protocol", False)
                and value not in drivers
            ):
                raise ValueError(
                    f"driver lacks catalogue declaration: {module.__name__}.{node.name}"
                )


def validate_payload(payload, entries):
    """Check exact membership, references and constructor/evidence contracts."""
    validate_public_api(entries)
    expected = {
        "primitives": {row.name for row in entries if row.declaration.category == "primitive"},
        "components": {row["name"] for row in component_records(entries)},
        "drivers": {row["name"] for row in driver_records(entries)},
        "representations": {row["name"] for row in representation_records(entries)},
        "analyses": {row["name"] for row in analysis_records(entries)},
    }
    for section, names in expected.items():
        actual = [row["name"] for row in payload[section]]
        if len(actual) != len(set(actual)) or set(actual) != names:
            raise ValueError(f"{section}: catalogue membership differs from implementations")
    import claasp.unit_types as unit_types

    domain_names = {name for name in unit_types.__all__ if name != "UnitType"}
    for row in payload["representations"]:
        if not set(row["domains"]) <= domain_names:
            raise ValueError(f"{row['name']}: unknown domains")
        if row["scope"] not in {"generic_graph", "component", "result"}:
            raise ValueError(f"{row['name']}: unknown scope")
        for field, section in (("components", "components"), ("drivers", "drivers")):
            if not set(row[field]) <= expected[section]:
                raise ValueError(f"{row['name']}: unknown {field}")
    for row in payload["analyses"]:
        for field, section in (
            ("required_components", "components"),
            ("drivers", "drivers"),
            ("representations", "representations"),
            ("primitives", "primitives"),
        ):
            if not set(row[field]) <= expected[section]:
                raise ValueError(f"{row['name']}: unknown {field}")
    declarations = {
        row.name: row.declaration for row in entries if row.declaration.category == "primitive"
    }
    for row in payload["primitives"]:
        signature = inspect.signature(declarations[row["name"]].implementation)
        for parameters in row["parameter_sets"]:
            # Constructor defaults may supply omitted parameters; binding catches
            # both unknown keys and missing required inputs (including examples).
            signature.bind(**parameters["values"])
        for evidence in row["fixed_evidence"]:
            if not (ROOT / evidence).is_file():
                raise ValueError(f"{row['name']}: missing evidence file {evidence}")
