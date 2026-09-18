"""Typed contracts for semantic component-property analysis.

The module deliberately contains no Sage, solver, or plotting dependency.
Concrete analyzers added by later M10.11 slices consume these contracts.
"""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from functools import lru_cache
from hashlib import sha256
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


_LOOKUP_PROPERTIES = frozenset({
    ComponentProperty.DIFFERENTIAL_UNIFORMITY,
    ComponentProperty.NONLINEARITY,
    ComponentProperty.ALGEBRAIC_DEGREE,
    ComponentProperty.BALANCED,
    ComponentProperty.APN,
    ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
    ComponentProperty.LINEAR_BRANCH_NUMBER,
    ComponentProperty.BOOMERANG_UNIFORMITY,
})


def analyze_component_property(
    component,
    request: PropertyRequest,
    *,
    graph_locations: tuple[str, ...] = (),
    primitive: str | None = None,
    realization: str | None = None,
) -> ComponentPropertyResult:
    """Analyze one semantic component under an explicit typed request.

    Unsupported component/property/domain combinations return a typed
    unavailable result. Invalid component parameters continue to raise at
    component construction boundaries.
    """

    from claasp_next.components import BinaryAffineMap, BitVectorSBox, LinearMap, Permutation, SBox

    if isinstance(component, (BitVectorSBox, SBox)):
        return _analyze_lookup_component(
            component, request, graph_locations, primitive, realization
        )
    if isinstance(component, (LinearMap, BinaryAffineMap, Permutation)):
        return _analyze_linear_component(
            component, request, graph_locations, primitive, realization
        )
    provenance = ComponentAnalysisProvenance(
        semantic_component_key(component, request.domain).component_type,
        "core_dispatch",
        primitive,
        realization,
        graph_locations,
    )
    return unavailable_result(
        request,
        provenance,
        DiagnosticCode.UNSUPPORTED_COMPONENT,
        f"no core component-property analyzer for {type(component).__name__}",
    )


def analyze_lookup_table(
    table,
    request: PropertyRequest,
    *,
    graph_locations: tuple[str, ...] = (),
) -> ComponentPropertyResult:
    """Analyze an immutable lookup table without constructing a graph.

    >>> from claasp_next.analysis.component_properties import *
    >>> from claasp_next.components import LookupTable
    >>> table = LookupTable((0, 1, 3, 2), 2)
    >>> result = analyze_lookup_table(table, PropertyRequest(
    ...     ComponentProperty.DIFFERENTIAL_UNIFORMITY, PropertyDomain.LOOKUP_TABLE))
    >>> result.value, result.claim.value
    (4, 'exact')
    """

    from claasp_next.components import LookupTable

    if not isinstance(table, LookupTable):
        raise TypeError("lookup analysis requires a LookupTable")
    identity = _lookup_identity(table.values, table.input_bit_size, table.output_bit_size)
    provenance = ComponentAnalysisProvenance(
        identity, "exact_exhaustive_lookup", graph_locations=graph_locations
    )
    return _lookup_result(table.values, table.input_bit_size, table.output_bit_size, request, provenance)


def _analyze_lookup_component(component, request, graph_locations, primitive, realization):
    from claasp_next.components import LookupTable

    input_width = component.inputs[0].value_type.encoded_bit_size
    output_width = component.output_type.encoded_bit_size
    if input_width is None or output_width is None:
        raise ValueError("lookup component domains must have canonical bit encodings")
    table = LookupTable(component.table, input_width, output_width)
    provenance = ComponentAnalysisProvenance(
        _lookup_identity(table.values, input_width, output_width),
        "exact_exhaustive_lookup",
        primitive,
        realization,
        graph_locations,
    )
    return _lookup_result(table.values, input_width, output_width, request, provenance)


def _lookup_result(table, input_width, output_width, request, provenance):
    if request.domain not in {PropertyDomain.LOOKUP_TABLE, PropertyDomain.BOOLEAN}:
        return unavailable_result(
            request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN,
            f"lookup properties do not apply in {request.domain.value!r}",
        )
    if request.property not in _LOOKUP_PROPERTIES:
        return unavailable_result(
            request, provenance, DiagnosticCode.UNSUPPORTED_PROPERTY,
            f"{request.property.value!r} is not a lookup-table property",
        )
    if request.property is ComponentProperty.BOOMERANG_UNIFORMITY:
        if input_width != output_width or sorted(table) != list(range(1 << input_width)):
            return unavailable_result(
                request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN,
                "boomerang uniformity requires a bijective square lookup table",
            )
    facts = _exact_lookup_facts(tuple(table), input_width, output_width)
    return ComponentPropertyResult(
        request, PropertyClaim.EXACT, facts[request.property], True, provenance
    )


def _lookup_identity(table, input_width, output_width):
    digest = sha256(bytes(table)).hexdigest()[:16]
    return f"lookup_table:{input_width}->{output_width}:{digest}"


@lru_cache(maxsize=128)
def _exact_lookup_facts(table, input_width, output_width):
    from claasp_next.components import LookupTable
    from claasp_next.representations.constraints.polynomial import vectorial_anf
    from claasp_next.semantics.cryptanalysis import (
        SBoxBoomerangSemantics, SBoxTransitionSemantics,
    )

    LookupTable(table, input_width, output_width)
    input_size, output_size = 1 << input_width, 1 << output_width
    if input_width == output_width:
        transitions = SBoxTransitionSemantics(table)
        ddt = transitions.difference_distribution_table()
        walsh = transitions.walsh_correlation_table()
    else:
        ddt = _rectangular_ddt(table, input_size, output_size)
        walsh = _rectangular_walsh(table, input_size, output_size)
    differential_uniformity = max(max(row) for row in ddt[1:])
    maximum_walsh = max(
        abs(walsh[input_mask][output_mask])
        for input_mask in range(input_size)
        for output_mask in range(1, output_size)
    )
    nonlinearity = (input_size // 2) - (maximum_walsh // 2)
    anfs = vectorial_anf(table)
    algebraic_degree = max(polynomial.degree for polynomial in anfs)
    counts = [0] * output_size
    for value in table:
        counts[value] += 1
    balanced = len(set(counts)) == 1
    differential_branch = min(
        alpha.bit_count() + beta.bit_count()
        for alpha in range(1, input_size)
        for beta in range(output_size)
        if ddt[alpha][beta]
    )
    linear_branch = min(
        alpha.bit_count() + beta.bit_count()
        for alpha in range(input_size)
        for beta in range(1, output_size)
        if walsh[alpha][beta]
    )
    boomerang = None
    if input_width == output_width and sorted(table) == list(range(input_size)):
        semantics = SBoxBoomerangSemantics(table)
        boomerang = max(
            semantics.connectivity(alpha, beta).count
            for alpha in range(1, input_size)
            for beta in range(1, output_size)
        )
    return MappingProxyType({
        ComponentProperty.DIFFERENTIAL_UNIFORMITY: differential_uniformity,
        ComponentProperty.NONLINEARITY: nonlinearity,
        ComponentProperty.ALGEBRAIC_DEGREE: algebraic_degree,
        ComponentProperty.BALANCED: balanced,
        ComponentProperty.APN: differential_uniformity == 2,
        ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER: differential_branch,
        ComponentProperty.LINEAR_BRANCH_NUMBER: linear_branch,
        ComponentProperty.BOOMERANG_UNIFORMITY: boomerang,
    })


def _rectangular_ddt(table, input_size, output_size):
    rows = []
    for alpha in range(input_size):
        row = [0] * output_size
        for value in range(input_size):
            row[table[value] ^ table[value ^ alpha]] += 1
        rows.append(tuple(row))
    return tuple(rows)


def _rectangular_walsh(table, input_size, output_size):
    rows = [[0] * output_size for _ in range(input_size)]
    for beta in range(output_size):
        values = [1 if (output & beta).bit_count() % 2 == 0 else -1 for output in table]
        stride = 1
        while stride < input_size:
            for start in range(0, input_size, 2 * stride):
                for offset in range(stride):
                    left, right = values[start + offset], values[start + offset + stride]
                    values[start + offset] = left + right
                    values[start + offset + stride] = left - right
            stride *= 2
        for alpha, coefficient in enumerate(values):
            rows[alpha][beta] = coefficient
    return tuple(tuple(row) for row in rows)


def _analyze_linear_component(component, request, graph_locations, primitive, realization):
    from claasp_next.components import BinaryAffineMap, LinearMap, Permutation
    from claasp_next.domains import BinaryExtensionField, Bit
    from claasp_next.analysis.linear_properties import (
        exact_branch_number, exact_matrix_order, expand_binary_field_matrix,
        matrix_is_mds, matrix_rank, permutation_order,
    )

    key = semantic_component_key(component, request.domain)
    provenance = ComponentAnalysisProvenance(
        _semantic_key_identity(key), "exact_field_linear_algebra",
        primitive, realization, graph_locations,
    )
    supported = {
        ComponentProperty.RANK, ComponentProperty.INVERTIBLE,
        ComponentProperty.ORDER, ComponentProperty.MDS,
        ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
        ComponentProperty.LINEAR_BRANCH_NUMBER,
    }
    if request.property not in supported:
        return unavailable_result(
            request, provenance, DiagnosticCode.UNSUPPORTED_PROPERTY,
            f"{request.property.value!r} is not a linear-map property",
        )
    if isinstance(component, Permutation):
        width = component.output_type.unit_count
        values = {
            ComponentProperty.RANK: width,
            ComponentProperty.INVERTIBLE: True,
            ComponentProperty.ORDER: permutation_order(component.mapping),
            ComponentProperty.MDS: width == 1,
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER: 2,
            ComponentProperty.LINEAR_BRANCH_NUMBER: 2,
        }
        return ComponentPropertyResult(
            request, PropertyClaim.EXACT, values[request.property], True, provenance
        )

    matrix = component.matrix
    domain = Bit() if isinstance(component, BinaryAffineMap) else component.inputs[0].value_type.domain
    analysis_matrix = matrix
    analysis_domain = domain
    if request.domain is PropertyDomain.BIT_LINEAR and isinstance(domain, BinaryExtensionField):
        analysis_matrix = expand_binary_field_matrix(matrix, domain)
        analysis_domain = Bit()
    elif request.domain is PropertyDomain.BIT_LINEAR and not isinstance(domain, Bit):
        return unavailable_result(
            request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN,
            "bit-linear analysis requires Bit or binary-extension-field semantics",
        )
    elif request.domain in {PropertyDomain.WORD_LINEAR, PropertyDomain.FINITE_FIELD_LINEAR}:
        if isinstance(component, BinaryAffineMap) or isinstance(domain, Bit):
            return unavailable_result(
                request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN,
                "word/field analysis requires a non-binary scalar field matrix",
            )
    else:
        if request.domain is not PropertyDomain.BIT_LINEAR:
            return unavailable_result(
                request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN,
                f"linear properties do not apply in {request.domain.value!r}",
            )

    rank = matrix_rank(analysis_matrix, analysis_domain)
    square = len(analysis_matrix) == len(analysis_matrix[0])
    if request.property is ComponentProperty.RANK:
        value = rank
    elif request.property is ComponentProperty.INVERTIBLE:
        value = square and rank == len(analysis_matrix)
    elif request.property is ComponentProperty.MDS:
        value = matrix_is_mds(analysis_matrix, analysis_domain)
    elif request.property is ComponentProperty.ORDER:
        maximum_steps = request.option_map.get("maximum_steps", 65536)
        if not isinstance(maximum_steps, int) or isinstance(maximum_steps, bool) or maximum_steps <= 0:
            raise ValueError("maximum_steps must be a positive integer")
        offset = None
        if isinstance(component, BinaryAffineMap):
            degree = len(component.matrix)
            offset = tuple((component.offset >> (degree - 1 - bit)) & 1 for bit in range(degree))
        value = exact_matrix_order(
            analysis_matrix, analysis_domain, maximum_steps=maximum_steps, offset=offset
        )
        if value is None:
            code = DiagnosticCode.INAPPLICABLE_DOMAIN if not square or rank != len(analysis_matrix) else DiagnosticCode.BUDGET_EXHAUSTED
            message = "order requires an invertible square map" if code is DiagnosticCode.INAPPLICABLE_DOMAIN else "matrix order was not reached within maximum_steps"
            return unavailable_result(request, provenance, code, message)
    else:
        maximum_vectors = request.option_map.get("maximum_vectors", 65536)
        if not isinstance(maximum_vectors, int) or isinstance(maximum_vectors, bool) or maximum_vectors <= 0:
            raise ValueError("maximum_vectors must be a positive integer")
        value = exact_branch_number(
            analysis_matrix, analysis_domain,
            linear=request.property is ComponentProperty.LINEAR_BRANCH_NUMBER,
            maximum_vectors=maximum_vectors,
        )
        if value is None:
            return unavailable_result(
                request, provenance, DiagnosticCode.BUDGET_EXHAUSTED,
                "exact branch-number enumeration exceeds maximum_vectors",
            )
    return ComponentPropertyResult(
        request, PropertyClaim.EXACT, value, True, provenance
    )


def _semantic_key_identity(key):
    digest = sha256(repr((key.component_type, key.input_types, key.output_type, key.parameters, key.domain)).encode()).hexdigest()[:16]
    return f"{key.component_type.rsplit('.', 1)[-1]}:{key.domain.value}:{digest}"


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
    "analyze_component_property",
    "analyze_lookup_table",
    "semantic_component_groups",
    "semantic_component_key",
    "unavailable_result",
]
