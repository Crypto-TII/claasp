"""Private declarations shared by catalogue generation and implementation owners.

Declarations hold real objects, never import-path strings. They do not register
objects globally, probe dependencies, or import optional execution backends.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class _Entry:
    category: str
    implementation: Any
    metadata: Mapping[str, Any]


def _entry(category: str, implementation: Any, **metadata: Any) -> _Entry:
    if category not in {"primitive", "driver", "representation", "analysis", "analysis_api"}:
        raise ValueError(f"unknown catalogue category: {category!r}")
    if not callable(implementation):
        raise TypeError("catalogue implementations must be classes or functions")
    fields = {
        "primitive": {"name", "evidence", "labels", "example"},
        "driver": {"name", "kind", "availability", "target", "target_parameter"},
        "representation": {"name", "kind", "components", "domains", "drivers", "scope"},
        "analysis": {
            "name",
            "kind",
            "evidence",
            "representations",
            "drivers",
            "required_components",
            "primitives",
            "restriction",
        },
        "analysis_api": set(),
    }
    required = {
        "primitive": set(),
        "driver": {"name", "kind", "availability"},
        "representation": fields["representation"],
        "analysis": fields["analysis"],
        "analysis_api": set(),
    }
    missing = required[category] - set(metadata)
    if missing:
        raise ValueError(f"missing {category} metadata: {sorted(missing)}")
    unknown = set(metadata) - fields[category]
    if unknown:
        raise ValueError(f"unknown {category} metadata: {sorted(unknown)}")
    if category == "driver" and metadata.get("kind") not in {
        "solver",
        "external_tool",
        "renderer",
        "compiler",
        "execution_engine",
        "analysis_driver",
    }:
        raise ValueError("unknown driver kind")
    if category == "driver" and metadata.get("availability") not in {
        "builtin",
        "executable",
        "python_module",
        "minizinc_solver",
    }:
        raise ValueError("unknown driver availability rule")
    return _Entry(category, implementation, MappingProxyType(metadata))
