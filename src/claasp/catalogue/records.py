"""Immutable records returned by catalogue discovery queries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


def _freeze(value):
    if isinstance(value, dict):
        return tuple((key, _freeze(item)) for key, item in sorted(value.items()))
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, tuple):
        if all(
            isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
            for item in value
        ):
            return {key: _thaw(item) for key, item in value}
        return tuple(_thaw(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class InputRecord:
    """One named primitive input and its study-default visibility.

    EXAMPLES::

        >>> from claasp.catalogue import catalogue
        >>> tuple((item.name, item.visibility) for item in catalogue.primitive("AES").inputs)
        (('plaintext', 'public'), ('key', 'secret'))
    """

    name: str
    role: str
    visibility: str


@dataclass(frozen=True, slots=True)
class RealizationRecord:
    """Discovery metadata for one graph realization.

    EXAMPLES::

        >>> from claasp.catalogue import catalogue
        >>> catalogue.realizations(primitive="AES")[0].identity
        'AES:lookup'
    """

    primitive: str
    name: str
    capabilities: frozenset[str]
    structure: frozenset[str]
    maturity: str
    provenance: tuple[str, ...]
    priority: int

    @property
    def identity(self) -> str:
        """Return the stable ``primitive:realization`` identity."""
        return f"{self.primitive}:{self.name}"


@dataclass(frozen=True, slots=True)
class ParameterSetRecord:
    """A named immutable constructor-parameter set.

    EXAMPLES::

        >>> from claasp.catalogue import ParameterSetRecord
        >>> record = ParameterSetRecord.from_mapping("Toy", "small", {"rounds": 2})
        >>> dict(record.values)
        {'rounds': 2}
    """

    primitive: str
    name: str
    _values: tuple[tuple[str, object], ...]

    @classmethod
    def from_mapping(cls, primitive: str, name: str, values: Mapping[str, object]):
        """Freeze a constructor-parameter mapping into a catalogue record."""
        return cls(primitive, name, _freeze(dict(values)))

    @property
    def values(self) -> Mapping[str, object]:
        """Return a read-only mapping of constructor parameter values."""

        return MappingProxyType(_thaw(self._values))


@dataclass(frozen=True, slots=True)
class PrimitiveRecord:
    """Committed classification and typed-boundary metadata for a primitive.

    ``bijectivity_obligation`` applies to the designated data/state input of
    each named parameter set while every auxiliary input is retained. It is
    separate from the whole-arity ``kind`` classification.

    EXAMPLES::

        >>> from claasp.catalogue import catalogue
        >>> record = catalogue.primitive("AES")
        >>> (record.qualified_name, record.kind)
        ('claasp.primitives.block_ciphers.aes.AES', 'block_cipher')
    """

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
    domains: frozenset[str]
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
        """Return the importable module and public class name."""
        return f"{self.module}.{self.name}"


@dataclass(frozen=True, slots=True)
class ComponentRecord:
    """A public v5 base component and its teaching primitive wrapper.

    EXAMPLES::

        >>> from claasp.catalogue import catalogue
        >>> catalogue.components(names="SBox")[0].primitive_wrapper
        'SBox'
    """

    name: str
    module: str
    primitive_wrapper: str


@dataclass(frozen=True, slots=True)
class RepresentationRecord:
    """One declared representation and its conservative compatibility edges.

    EXAMPLES::

        >>> from claasp.catalogue import catalogue
        >>> sorted(catalogue.representation("boolean_cnf").domains)
        ['Bit', 'Word']
    """

    name: str
    kind: str
    implementation: str
    components: frozenset[str]
    domains: frozenset[str]
    drivers: frozenset[str]
    scope: str


@dataclass(frozen=True, slots=True)
class AnalysisRecord:
    """One discoverable analysis and its representation requirements.

    EXAMPLES::

        >>> from claasp.catalogue import catalogue
        >>> any(item.name == "avalanche" for item in catalogue.analyses(primitive="AES"))
        True
    """

    name: str
    entry_point: str
    kind: str
    evidence: str
    representations: frozenset[str]
    drivers: frozenset[str]
    required_components: frozenset[str]
    primitives: frozenset[str]
    restriction: str | None


@dataclass(frozen=True, slots=True)
class DriverRecord:
    """A result-producing driver and its side-effect-free availability rule.

    EXAMPLES::

        >>> from claasp.catalogue import catalogue
        >>> catalogue.driver("python_scalar").availability
        'builtin'
    """

    name: str
    kind: str
    availability: str
    target: str | None
    implementation: str
    representations: frozenset[str]


@dataclass(frozen=True, slots=True)
class DriverAvailabilityRecord:
    """Result of an explicit, lazy driver availability probe.

    EXAMPLES::

        >>> from claasp.catalogue import catalogue
        >>> probe = catalogue.driver_availability("python_scalar")
        >>> (probe.available, probe.detail)
        (True, 'part of the dependency-free core')
    """

    driver: DriverRecord
    available: bool
    resolved: str | None = None
    detail: str | None = None


__all__ = [
    "AnalysisRecord",
    "ComponentRecord",
    "DriverAvailabilityRecord",
    "DriverRecord",
    "InputRecord",
    "ParameterSetRecord",
    "PrimitiveRecord",
    "RealizationRecord",
    "RepresentationRecord",
]
