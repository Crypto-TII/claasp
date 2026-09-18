"""Typed contracts for semantic component-property analysis.

The module deliberately contains no Sage, solver, or plotting dependency.
Concrete analyzers added by later M10.11 slices consume these contracts.
"""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from types import MappingProxyType
from typing import Protocol

from claasp_next.provenance import DriverIdentity


class PropertyClaim(str, Enum):
    """Strength of the evidence carried by a property result."""

    EXACT = "exact"
    PROVED_LOWER_BOUND = "proved_lower_bound"
    PROVED_UPPER_BOUND = "proved_upper_bound"
    EMPIRICAL = "empirical"
    UNAVAILABLE = "unavailable"


class PropertyDomain(str, Enum):
    """Mathematical domain in which a component property is interpreted."""

    LOOKUP_TABLE = "lookup_table"
    BOOLEAN = "boolean"
    BIT_LINEAR = "bit_linear"
    WORD_LINEAR = "word_linear"
    FINITE_FIELD_LINEAR = "finite_field_linear"
    WORD_OPERATION = "word_operation"
    FEEDBACK_REGISTER = "feedback_register"


class ComponentProperty(str, Enum):
    """Specification-oriented component properties supported by M10.11."""

    DIFFERENTIAL_UNIFORMITY = "differential_uniformity"
    NONLINEARITY = "nonlinearity"
    ALGEBRAIC_DEGREE = "algebraic_degree"
    BALANCED = "balanced"
    APN = "apn"
    DIFFERENTIAL_BRANCH_NUMBER = "differential_branch_number"
    LINEAR_BRANCH_NUMBER = "linear_branch_number"
    BOOMERANG_UNIFORMITY = "boomerang_uniformity"
    RANK = "rank"
    INVERTIBLE = "invertible"
    ORDER = "order"
    MDS = "mds"
    TERM_COUNT = "term_count"
    VARIABLE_COUNT = "variable_count"
    LINEAR = "linear"
    REGISTER_STRUCTURE = "register_structure"
    CONNECTION_POLYNOMIAL = "connection_polynomial"


class DiagnosticCode(str, Enum):
    """Stable reason why a requested property cannot be returned."""

    UNSUPPORTED_COMPONENT = "unsupported_component"
    UNSUPPORTED_PROPERTY = "unsupported_property"
    INAPPLICABLE_DOMAIN = "inapplicable_domain"
    INVALID_PARAMETERS = "invalid_parameters"
    DRIVER_UNAVAILABLE = "driver_unavailable"
    BUDGET_EXHAUSTED = "budget_exhausted"


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class PropertyDiagnostic:
    """Typed analysis diagnostic with a stable machine-readable code."""

    code: DiagnosticCode
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, DiagnosticCode):
            object.__setattr__(self, "code", DiagnosticCode(self.code))
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("diagnostic message must be a non-empty string")


@dataclass(frozen=True, slots=True)
class PropertyRequest:
    """One property request with explicit mathematical domain and options.

    >>> request = PropertyRequest(ComponentProperty.RANK, PropertyDomain.BIT_LINEAR)
    >>> request.property.value, request.domain.value
    ('rank', 'bit_linear')
    """

    property: ComponentProperty
    domain: PropertyDomain
    options: tuple[tuple[str, object], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.property, ComponentProperty):
            object.__setattr__(self, "property", ComponentProperty(self.property))
        if not isinstance(self.domain, PropertyDomain):
            object.__setattr__(self, "domain", PropertyDomain(self.domain))
        if not isinstance(self.options, tuple) or any(
            not isinstance(item, tuple) or len(item) != 2
            or not isinstance(item[0], str) or not item[0]
            for item in self.options
        ):
            raise TypeError("property options must be (name, value) pairs")
        if len({name for name, _ in self.options}) != len(self.options):
            raise ValueError("property option names must be unique")
        object.__setattr__(
            self, "options", tuple((name, _freeze(value)) for name, value in self.options)
        )

    @property
    def option_map(self) -> Mapping[str, object]:
        """Return options through a read-only mapping."""

        return MappingProxyType(dict(self.options))


@dataclass(frozen=True, slots=True)
class ComponentAnalysisProvenance:
    """Semantic identity and evidence locations, separate from a driver.

    ``semantic_identity`` never contains an incidental component identifier.
    Graph locations are optional evidence references only.
    """

    semantic_identity: str
    analysis_method: str
    primitive: str | None = None
    realization: str | None = None
    graph_locations: tuple[str, ...] = ()
    driver: DriverIdentity | None = None

    def __post_init__(self) -> None:
        if not self.semantic_identity or not isinstance(self.semantic_identity, str):
            raise ValueError("semantic identity must be a non-empty string")
        if not self.analysis_method or not isinstance(self.analysis_method, str):
            raise ValueError("analysis method must be a non-empty string")
        if any(not isinstance(item, str) or not item for item in self.graph_locations):
            raise ValueError("graph locations must be non-empty strings")
        if self.driver is not None and not isinstance(self.driver, DriverIdentity):
            raise TypeError("analysis driver must be a DriverIdentity or None")


@dataclass(frozen=True, slots=True)
class ComponentPropertyResult:
    """Immutable value, evidence qualification, and provenance for one request."""

    request: PropertyRequest
    claim: PropertyClaim
    value: object | None
    complete: bool
    provenance: ComponentAnalysisProvenance
    diagnostic: PropertyDiagnostic | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request, PropertyRequest):
            raise TypeError("result request must be a PropertyRequest")
        if not isinstance(self.claim, PropertyClaim):
            object.__setattr__(self, "claim", PropertyClaim(self.claim))
        if not isinstance(self.complete, bool):
            raise TypeError("result completeness must be Boolean")
        if not isinstance(self.provenance, ComponentAnalysisProvenance):
            raise TypeError("result provenance must be ComponentAnalysisProvenance")
        if self.claim is PropertyClaim.EXACT and not self.complete:
            raise ValueError("an exact result must prove complete coverage")
        if self.claim is PropertyClaim.UNAVAILABLE:
            if self.value is not None or self.diagnostic is None:
                raise ValueError("unavailable results require a diagnostic and no value")
        elif self.diagnostic is not None:
            raise ValueError("available results cannot carry an unavailable diagnostic")
        object.__setattr__(self, "value", _freeze(self.value))

    @property
    def is_available(self) -> bool:
        """Return whether the request produced mathematical evidence."""

        return self.claim is not PropertyClaim.UNAVAILABLE


class ComponentPropertyDriver(Protocol):
    """Protocol implemented by optional heavy component-analysis drivers."""

    identity: DriverIdentity

    def analyze(self, component, request: PropertyRequest) -> ComponentPropertyResult:
        """Analyze ``component`` under exactly the supplied typed request."""


@dataclass(frozen=True, slots=True)
class ComponentSemanticKey:
    """Identity of one operation independent of graph location and inputs."""

    component_type: str
    input_types: tuple[object, ...]
    output_type: object
    parameters: tuple[tuple[str, object], ...]
    domain: PropertyDomain


@dataclass(frozen=True, slots=True)
class ComponentOccurrence:
    """One semantic component and its optional stable graph location."""

    component: object
    graph_location: str | None


@dataclass(frozen=True, slots=True)
class ComponentGroup:
    """Equivalent semantic operations discovered in an immutable graph."""

    key: ComponentSemanticKey
    occurrences: tuple[ComponentOccurrence, ...]

    @property
    def count(self) -> int:
        """Return the number of graph occurrences in this semantic group."""

        return len(self.occurrences)

    @property
    def representative(self):
        """Return a representative component without making it group identity."""

        return self.occurrences[0].component


def semantic_component_key(component, domain: PropertyDomain) -> ComponentSemanticKey:
    """Return a typed key excluding sources and incidental component ids.

    >>> from claasp_next.components import LookupTable
    >>> table = LookupTable([0, 1, 3, 2], 2)
    >>> table.is_bijective()
    True

    ``LookupTable`` is a parameter object rather than a graph component; graph
    operations are validated explicitly so structural bindings cannot enter
    analysis grouping.
    """

    from claasp_next.graph import Component

    if not isinstance(component, Component):
        raise TypeError("semantic grouping requires a Component")
    if not isinstance(domain, PropertyDomain):
        domain = PropertyDomain(domain)
    parameters = []
    if is_dataclass(component):
        for field in fields(component):
            if field.name in {"component_id", "inputs", "output_type"}:
                continue
            parameters.append((field.name, _freeze_hashable(getattr(component, field.name))))
    return ComponentSemanticKey(
        component_type=f"{type(component).__module__}.{type(component).__qualname__}",
        input_types=tuple(selection.value_type for selection in component.inputs),
        output_type=component.output_type,
        parameters=tuple(parameters),
        domain=domain,
    )


def semantic_component_groups(primitive, domain: PropertyDomain) -> tuple[ComponentGroup, ...]:
    """Group graph operations by semantics while ignoring structural bindings.

    The returned order follows the first semantic occurrence only for
    presentation stability; it is not part of a group's identity.
    """

    from claasp_next.graph import Primitive

    if not isinstance(primitive, Primitive):
        raise TypeError("component discovery requires a Primitive")
    if not isinstance(domain, PropertyDomain):
        domain = PropertyDomain(domain)

    locations = {}
    for round_index, round_ in enumerate(primitive.rounds):
        for component_index, component in enumerate(round_.components):
            locations[id(component)] = f"round[{round_index}]/component[{component_index}]"

    grouped: dict[ComponentSemanticKey, list[ComponentOccurrence]] = {}
    for component in primitive.components:
        key = semantic_component_key(component, domain)
        grouped.setdefault(key, []).append(
            ComponentOccurrence(component, locations.get(id(component)))
        )
    return tuple(
        ComponentGroup(key, tuple(occurrences))
        for key, occurrences in grouped.items()
    )


def _freeze_hashable(value):
    if isinstance(value, Mapping):
        return tuple(sorted((key, _freeze_hashable(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_hashable(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_hashable(item) for item in value)
    try:
        hash(value)
    except TypeError as error:
        raise TypeError(f"semantic parameter {value!r} is not immutable") from error
    return value


def unavailable_result(
    request: PropertyRequest,
    provenance: ComponentAnalysisProvenance,
    code: DiagnosticCode,
    message: str,
) -> ComponentPropertyResult:
    """Construct a precise unavailable result without fabricating a value."""

    return ComponentPropertyResult(
        request=request,
        claim=PropertyClaim.UNAVAILABLE,
        value=None,
        complete=False,
        provenance=provenance,
        diagnostic=PropertyDiagnostic(code, message),
    )


__all__ = [
    "ComponentAnalysisProvenance",
    "ComponentGroup",
    "ComponentOccurrence",
    "ComponentProperty",
    "ComponentPropertyDriver",
    "ComponentPropertyResult",
    "ComponentSemanticKey",
    "DiagnosticCode",
    "PropertyClaim",
    "PropertyDiagnostic",
    "PropertyDomain",
    "PropertyRequest",
    "semantic_component_groups",
    "semantic_component_key",
    "unavailable_result",
]
