"""Immutable records returned by catalogue discovery queries."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


def _freeze(value):
    if isinstance(value, dict):
        return tuple((key, _freeze(item)) for key, item in sorted(value.items()))
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, tuple):
        if all(isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str) for item in value):
            return {key: _thaw(item) for key, item in value}
        return tuple(_thaw(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class InputRecord:
    """One named primitive input and its study-default visibility."""

    name: str
    role: str
    visibility: str


@dataclass(frozen=True, slots=True)
class RealizationRecord:
    """Discovery metadata for one graph realization."""

    primitive: str
    name: str
    capabilities: frozenset[str]
    structure: frozenset[str]
    maturity: str
    provenance: tuple[str, ...]
    priority: int

    @property
    def identity(self) -> str:
        return f"{self.primitive}:{self.name}"


@dataclass(frozen=True, slots=True)
class ParameterSetRecord:
    """A named immutable constructor-parameter set."""

    primitive: str
    name: str
    _values: tuple[tuple[str, object], ...]

    @classmethod
    def from_mapping(cls, primitive: str, name: str, values: Mapping[str, object]):
        return cls(primitive, name, _freeze(dict(values)))

    @property
    def values(self) -> Mapping[str, object]:
        """Return a read-only mapping of constructor parameter values."""

        return MappingProxyType(_thaw(self._values))


@dataclass(frozen=True, slots=True)
class PrimitiveRecord:
    """Committed classification and typed-boundary metadata for a primitive."""

    name: str
    official_name: str
    module: str
    category: str
    family: str
    kind: str
    inputs: tuple[InputRecord, ...]
    classified_input_roles: tuple[str, ...]
    bijectivity_obligation: bool
    components: frozenset[str]
    tags: frozenset[str]
    authenticity: str
    labels: frozenset[str]
    legacy_source: str | None
    classification_basis: str
    fixed_evidence: tuple[str, ...]
    parameter_sets: tuple[ParameterSetRecord, ...]
    realizations: tuple[RealizationRecord, ...]

    @property
    def qualified_name(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass(frozen=True, slots=True)
class ComponentRecord:
    """A public v5 base component and its teaching primitive wrapper."""

    name: str
    module: str
    primitive_wrapper: str


@dataclass(frozen=True, slots=True)
class DriverRecord:
    """A result-producing driver and its side-effect-free availability rule."""

    name: str
    kind: str
    availability: str
    target: str | None
    implementation: str


@dataclass(frozen=True, slots=True)
class DriverAvailabilityRecord:
    """Result of an explicit, lazy driver availability probe."""

    driver: DriverRecord
    available: bool
    resolved: str | None = None
    detail: str | None = None


__all__ = [
    "ComponentRecord", "DriverAvailabilityRecord", "DriverRecord", "InputRecord", "ParameterSetRecord",
    "PrimitiveRecord", "RealizationRecord",
]
