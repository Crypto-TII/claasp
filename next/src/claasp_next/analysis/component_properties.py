"""Typed contracts for semantic component-property analysis.

The module deliberately contains no Sage, solver, or plotting dependency.
Concrete analyzers added by later M10.11 slices consume these contracts.
"""

from collections.abc import Mapping
from dataclasses import dataclass
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
    "ComponentProperty",
    "ComponentPropertyDriver",
    "ComponentPropertyResult",
    "DiagnosticCode",
    "PropertyClaim",
    "PropertyDiagnostic",
    "PropertyDomain",
    "PropertyRequest",
    "unavailable_result",
]
