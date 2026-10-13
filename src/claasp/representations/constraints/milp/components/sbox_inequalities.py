"""Recovered small-S-box MILP inequality strategies."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from functools import cache
from importlib.resources import files
from math import log2

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    ConstraintModelProvenance,
    _unaudited_model,
    _verified_model,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    VariableKind,
)
from claasp.semantics.cryptanalysis import SBoxTransitionSemantics, TrailKind


class SBoxMILPInequalityStrategy(str, Enum):
    """Available recovered inequality selections.

    EXAMPLES::

        >>> tuple(item.value for item in SBoxMILPInequalityStrategy)
        ('convex_hull', 'greedy', 'minimum', 'espresso')
    """

    CONVEX_HULL = "convex_hull"
    GREEDY = "greedy"
    MINIMUM = "minimum"
    ESPRESSO = "espresso"


@dataclass(frozen=True, slots=True)
class SBoxMILPInequalityGroup:
    """Inequalities for one signed DDT/LAT count class.

    An inequality is ``constant + sum(coefficient[i] * bit[i]) >= 0``.

    EXAMPLES::

        >>> group = SBoxMILPInequalityGroup(2, ((-1, 1, 1),))
        >>> group.transition_count
        2
    """

    transition_count: int
    inequalities: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.transition_count, int) or self.transition_count == 0:
            raise ValueError("transition_count must be a nonzero integer")
        if not self.inequalities:
            raise ValueError("an inequality group cannot be empty")
        width = len(self.inequalities[0])
        if width < 2 or any(len(item) != width for item in self.inequalities):
            raise ValueError("inequalities must have one common nonzero width")
        if any(not isinstance(value, int) for item in self.inequalities for value in item):
            raise TypeError("inequality coefficients must be integers")


@dataclass(frozen=True, slots=True)
class SBoxMILPInequalitySystem:
    """A generated, validated small-S-box inequality system.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "present", TrailKind.XOR_DIFFERENTIAL,
        ...     SBoxMILPInequalityStrategy.GREEDY,
        ... )
        >>> (system.name, system.width, len(system.groups))
        ('present', 4, 2)
    """

    name: str
    table: tuple[int, ...]
    kind: TrailKind
    strategy: SBoxMILPInequalityStrategy
    groups: tuple[SBoxMILPInequalityGroup, ...]
    legacy_commit: str
    legacy_path: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name must be nonempty")
        if self.kind not in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR):
            raise ValueError("S-box inequalities require differential or linear semantics")
        if not isinstance(self.strategy, SBoxMILPInequalityStrategy):
            raise TypeError("strategy must be an SBoxMILPInequalityStrategy")
        if not self.legacy_commit or not self.legacy_path:
            raise ValueError("legacy source commit and path are required")
        semantics = SBoxTransitionSemantics(self.table)
        if semantics.width > 8:
            raise ValueError("recovered inequality strategies currently support at most 8 bits")
        expected_width = 1 + 2 * semantics.width
        if any(len(item) != expected_width for group in self.groups for item in group.inequalities):
            raise ValueError("inequality width does not match the S-box")
        counts = [group.transition_count for group in self.groups]
        if len(set(counts)) != len(counts):
            raise ValueError("transition-count groups must be unique")
        self._validate_relation(semantics)

    @property
    def width(self) -> int:
        """Return the input/output bit width."""

        return len(self.table).bit_length() - 1

    def _validate_relation(self, semantics: SBoxTransitionSemantics) -> None:
        if self.strategy is SBoxMILPInequalityStrategy.ESPRESSO:
            self._validate_espresso_relation(semantics)
            return
        by_count = {group.transition_count: group for group in self.groups}
        observed: set[int] = set()
        size = len(self.table)
        for source in range(size):
            for target in range(size):
                transition = (
                    semantics.xor_differential(source, target)
                    if self.kind is TrailKind.XOR_DIFFERENTIAL
                    else semantics.xor_linear(source, target)
                )
                signed_count = transition.sign * transition.numerator
                point = _point(source, target, self.width)
                if not (source or target):
                    continue
                for count, group in by_count.items():
                    accepted = all(_contains(item, point) for item in group.inequalities)
                    if accepted != (signed_count == count):
                        raise ValueError(
                            f"{self.strategy.value} inequalities disagree at "
                            f"({source}, {target}) for count {count}"
                        )
                if transition.is_possible:
                    observed.add(signed_count)
        if observed != set(by_count):
            raise ValueError("inequality groups do not cover every active transition class")

    def _validate_espresso_relation(self, semantics: SBoxTransitionSemantics) -> None:
        size = len(self.table)
        universe = (1 << (size * size)) - 1
        expected: dict[int, int] = {group.transition_count: 0 for group in self.groups}
        observed: set[int] = set()
        for source in range(size):
            for target in range(size):
                transition = (
                    semantics.xor_differential(source, target)
                    if self.kind is TrailKind.XOR_DIFFERENTIAL
                    else semantics.xor_linear(source, target)
                )
                if transition.is_possible and (source or target):
                    signed_count = transition.sign * transition.numerator
                    observed.add(signed_count)
                    if signed_count in expected:
                        expected[signed_count] |= 1 << (source * size + target)
        for group in self.groups:
            accepted = universe
            for inequality in group.inequalities:
                accepted &= ~_espresso_excluded_points(inequality, self.width)
            if accepted != expected[group.transition_count]:
                raise ValueError(
                    f"espresso inequalities disagree for count {group.transition_count}"
                )
        if observed != set(expected):
            raise ValueError("inequality groups do not cover every active transition class")


def load_bundled_sbox_milp_inequalities(
    name: str,
    kind: TrailKind,
    strategy: SBoxMILPInequalityStrategy,
) -> SBoxMILPInequalitySystem:
    """Load one generated system shipped with CLAASP.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "present", TrailKind.XOR_LINEAR,
        ...     SBoxMILPInequalityStrategy.MINIMUM,
        ... )
        >>> [(group.transition_count, len(group.inequalities)) for group in system.groups]
        [(-8, 6), (-4, 14), (4, 11), (8, 8)]
    """

    if not isinstance(name, str) or not name or not name.replace("_", "a").isalnum():
        raise ValueError("name must contain only letters, digits, and underscores")
    if kind not in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR):
        raise ValueError("S-box inequalities require differential or linear semantics")
    if not isinstance(strategy, SBoxMILPInequalityStrategy):
        raise TypeError("strategy must be an SBoxMILPInequalityStrategy")
    return _load_bundled_sbox_milp_inequalities(name, kind, strategy)


@cache
def _load_bundled_sbox_milp_inequalities(
    name: str,
    kind: TrailKind,
    strategy: SBoxMILPInequalityStrategy,
) -> SBoxMILPInequalitySystem:
    resource = files("claasp.representations.constraints.milp").joinpath(
        "data", f"{name}_sbox_milp_inequalities.json"
    )
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"no bundled S-box inequality system named {name!r}") from error
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported S-box inequality schema")
    selected = next((item for item in payload["systems"] if item["kind"] == kind.value), None)
    if selected is None:
        raise ValueError(f"bundle {name!r} does not contain {kind.value}")
    source = payload["legacy_source"]
    return SBoxMILPInequalitySystem(
        payload["name"],
        tuple(payload["table"]),
        kind,
        strategy,
        tuple(
            SBoxMILPInequalityGroup(
                item["transition_count"],
                tuple(tuple(inequality) for inequality in item["inequalities"][strategy.value]),
            )
            for item in selected["groups"]
        ),
        source["commit"],
        source["path"],
    )


class _SBoxInequalityFormulation:
    def __init__(
        self,
        system: SBoxMILPInequalitySystem,
        kind: TrailKind,
        strategy: SBoxMILPInequalityStrategy,
        provenance: ConstraintModelProvenance,
    ) -> None:
        if not isinstance(system, SBoxMILPInequalitySystem):
            raise TypeError("system must be an SBoxMILPInequalitySystem")
        if system.kind is not kind or system.strategy is not strategy:
            raise ValueError(f"system must contain {kind.value} {strategy.value} inequalities")
        self.system = system
        self.semantics = SBoxTransitionSemantics(system.table)
        self.kind = kind
        self.strategy = strategy
        self.model_provenance = provenance
        self.columns = tuple(
            f"{prefix}_{bit}" for prefix in ("input", "output") for bit in range(system.width)
        )
        self._selectors = {
            group.transition_count: _selector(group.transition_count) for group in system.groups
        }
        self._model: MILPModel | None = None

    @property
    def inequality_count(self) -> int:
        """Return the number of conditional facet inequalities."""

        return sum(len(group.inequalities) for group in self.system.groups)

    def milp_model(self, *, input_pattern=None, output_pattern=None) -> MILPModel:
        """Build the selected exact inequality formulation."""

        variables = tuple(
            LinearVariable(name, VariableKind.BINARY)
            for name in (*self.columns, "active", *self._selectors.values())
        )
        constraints = []
        for name in self.columns:
            constraints.append(
                LinearConstraint(
                    LinearExpression.from_terms({"active": 1, name: -1}),
                    ConstraintSense.GREATER_EQUAL,
                    0,
                    f"active_{name}",
                )
            )
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms({name: 1 for name in self.columns} | {"active": -1}),
                ConstraintSense.GREATER_EQUAL,
                0,
                "active_nonzero",
            )
        )
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms(
                    {name: 1 for name in self._selectors.values()} | {"active": -1}
                ),
                ConstraintSense.EQUAL,
                0,
                "select_transition_count",
            )
        )
        for group in self.system.groups:
            selector = self._selectors[group.transition_count]
            for number, inequality in enumerate(group.inequalities):
                constant, coefficients = inequality[0], inequality[1:]
                minimum = constant + sum(min(0, coefficient) for coefficient in coefficients)
                big_m = max(0, -minimum)
                terms = {
                    name: coefficient
                    for name, coefficient in zip(self.columns, coefficients)
                    if coefficient
                }
                if big_m:
                    terms[selector] = -big_m
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms(terms),
                        ConstraintSense.GREATER_EQUAL,
                        -constant - big_m,
                        f"count_{_count_token(group.transition_count)}_{number}",
                    )
                )
        for prefix, value in (("input", input_pattern), ("output", output_pattern)):
            if value is not None:
                self.semantics._validate_pattern(value)
                for bit in range(self.system.width):
                    constraints.append(
                        LinearConstraint(
                            LinearExpression.from_terms({f"{prefix}_{bit}": 1}),
                            ConstraintSense.EQUAL,
                            (value >> (self.system.width - 1 - bit)) & 1,
                            f"fixed_{prefix}_{bit}",
                        )
                    )
        objective = LinearExpression.from_terms(
            {
                selector: log2(len(self.system.table) / abs(count))
                for count, selector in self._selectors.items()
            }
        )
        self._model = MILPModel(
            variables,
            tuple(constraints),
            objective,
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def witness(self, input_pattern: int, output_pattern: int) -> dict[str, int]:
        """Return the canonical assignment for one possible transition."""

        self.semantics._validate_pattern(input_pattern)
        self.semantics._validate_pattern(output_pattern)
        transition = self._transition(input_pattern, output_pattern)
        if not transition.is_possible:
            raise ValueError("the requested S-box transition is impossible")
        signed_count = transition.sign * transition.numerator
        active = int(bool(input_pattern or output_pattern))
        if active and signed_count not in self._selectors:
            raise ValueError("the inequality system does not contain this transition class")
        point = _point(input_pattern, output_pattern, self.system.width)
        assignment = dict(zip(self.columns, point))
        assignment["active"] = active
        assignment.update(
            {
                selector: int(active and count == signed_count)
                for count, selector in self._selectors.items()
            }
        )
        return assignment

    def decode_transition(self, assignment):
        """Validate and decode one complete inequality-model assignment."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        if not self._model.is_feasible(assignment):
            raise ValueError("invalid S-box MILP witness")
        values = []
        for prefix in ("input", "output"):
            value = 0
            for bit in range(self.system.width):
                value = (value << 1) | round(assignment[f"{prefix}_{bit}"])
            values.append(value)
        transition = self._transition(*values)
        if (
            not transition.is_possible
            or abs(self._model.objective_value(assignment) - transition.weight) > 1e-7
        ):
            raise ValueError("S-box MILP objective disagrees with exact transition")
        return transition

    def _transition(self, source: int, target: int):
        return (
            self.semantics.xor_differential(source, target)
            if self.kind is TrailKind.XOR_DIFFERENTIAL
            else self.semantics.xor_linear(source, target)
        )


def _provenance(component_model: str, analysis_kind: str, encoding_name: str):
    if analysis_kind == "xor_differential" and encoding_name in {
        "legacy small-S-box convex-hull facets",
        "legacy greedy convex-hull facet reduction",
    }:
        return _verified_model(
            ConstraintBackend.MILP,
            component_model,
            analysis_kind,
            encoding_name,
            "https://eprint.iacr.org/2014/747",
            "Towards Finding the Best Characteristics of Some Bit-oriented Block Ciphers and Automatic Enumeration of (Related-key) Differential and Linear Characteristics with Predefined Properties",
            "section 3, Fact 1 and Algorithm 1; section 5, equation (6)",
        )
    if analysis_kind == "xor_differential" and encoding_name == (
        "legacy minimum-cardinality convex-hull facet cover"
    ):
        return _verified_model(
            ConstraintBackend.MILP,
            component_model,
            analysis_kind,
            encoding_name,
            "10.1007/978-3-319-69284-5_11",
            "New Algorithm for Modeling S-box in MILP Based Differential and Division Trail Search",
            "section 3, proposed inequality-reduction algorithm",
        )
    if analysis_kind == "xor_differential" and encoding_name == (
        "legacy large-S-box Espresso product of sums"
    ):
        return _verified_model(
            ConstraintBackend.MILP,
            component_model,
            analysis_kind,
            encoding_name,
            "10.13154/tosc.v2017.i4.99-129",
            "MILP Modeling for (Large) S-boxes to Optimize Probability of Differential Characteristics",
            "sections 3.1 and 3.2; section 4.1, Definition 1",
        )
    return _unaudited_model(
        ConstraintBackend.MILP,
        component_model,
        analysis_kind,
        encoding_name,
        "The legacy generator applies the strategy to signed LAT-count classes, but the searched primary sources do not specify the resulting signed-class selectors and objective.",
    )


class SBoxXorDifferentialConvexHullMILPModel(_SBoxInequalityFormulation):
    """Use every convex-hull facet for each nonzero DDT count class.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "present", TrailKind.XOR_DIFFERENTIAL,
        ...     SBoxMILPInequalityStrategy.CONVEX_HULL,
        ... )
        >>> relation = SBoxXorDifferentialConvexHullMILPModel(system)
        >>> _ = relation.milp_model(input_pattern=1, output_pattern=3)
        >>> relation.decode_transition(relation.witness(1, 3)).numerator
        4
    """

    model_provenance = _provenance(
        "SBoxXorDifferentialConvexHullMILPModel",
        "xor_differential",
        "legacy small-S-box convex-hull facets",
    )

    def __init__(self, system: SBoxMILPInequalitySystem) -> None:
        super().__init__(
            system,
            TrailKind.XOR_DIFFERENTIAL,
            SBoxMILPInequalityStrategy.CONVEX_HULL,
            type(self).model_provenance,
        )


class SBoxXorLinearConvexHullMILPModel(_SBoxInequalityFormulation):
    """Use every convex-hull facet for each signed nonzero LAT class.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "present", TrailKind.XOR_LINEAR,
        ...     SBoxMILPInequalityStrategy.CONVEX_HULL,
        ... )
        >>> relation = SBoxXorLinearConvexHullMILPModel(system)
        >>> model = relation.milp_model(input_pattern=1, output_pattern=5)
        >>> model.is_feasible(relation.witness(1, 5))
        True
    """

    model_provenance = _provenance(
        "SBoxXorLinearConvexHullMILPModel",
        "xor_linear",
        "legacy small-S-box convex-hull facets",
    )

    def __init__(self, system: SBoxMILPInequalitySystem) -> None:
        super().__init__(
            system,
            TrailKind.XOR_LINEAR,
            SBoxMILPInequalityStrategy.CONVEX_HULL,
            type(self).model_provenance,
        )


class SBoxXorDifferentialGreedyMILPModel(_SBoxInequalityFormulation):
    """Use the legacy greedy facet reduction for DDT count classes.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "present", TrailKind.XOR_DIFFERENTIAL,
        ...     SBoxMILPInequalityStrategy.GREEDY,
        ... )
        >>> relation = SBoxXorDifferentialGreedyMILPModel(system)
        >>> (relation.inequality_count, len(relation.milp_model().variables))
        (30, 11)
    """

    model_provenance = _provenance(
        "SBoxXorDifferentialGreedyMILPModel",
        "xor_differential",
        "legacy greedy convex-hull facet reduction",
    )

    def __init__(self, system: SBoxMILPInequalitySystem) -> None:
        super().__init__(
            system,
            TrailKind.XOR_DIFFERENTIAL,
            SBoxMILPInequalityStrategy.GREEDY,
            type(self).model_provenance,
        )


class SBoxXorLinearGreedyMILPModel(_SBoxInequalityFormulation):
    """Use the legacy greedy facet reduction for signed LAT classes.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "present", TrailKind.XOR_LINEAR,
        ...     SBoxMILPInequalityStrategy.GREEDY,
        ... )
        >>> relation = SBoxXorLinearGreedyMILPModel(system)
        >>> relation.inequality_count
        47
    """

    model_provenance = _provenance(
        "SBoxXorLinearGreedyMILPModel",
        "xor_linear",
        "legacy greedy convex-hull facet reduction",
    )

    def __init__(self, system: SBoxMILPInequalitySystem) -> None:
        super().__init__(
            system,
            TrailKind.XOR_LINEAR,
            SBoxMILPInequalityStrategy.GREEDY,
            type(self).model_provenance,
        )


class SBoxXorDifferentialMinimumMILPModel(_SBoxInequalityFormulation):
    """Use a Sage/GLPK minimum-cardinality facet cover for DDT classes.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "present", TrailKind.XOR_DIFFERENTIAL,
        ...     SBoxMILPInequalityStrategy.MINIMUM,
        ... )
        >>> relation = SBoxXorDifferentialMinimumMILPModel(system)
        >>> relation.inequality_count
        25
    """

    model_provenance = _provenance(
        "SBoxXorDifferentialMinimumMILPModel",
        "xor_differential",
        "legacy minimum-cardinality convex-hull facet cover",
    )

    def __init__(self, system: SBoxMILPInequalitySystem) -> None:
        super().__init__(
            system,
            TrailKind.XOR_DIFFERENTIAL,
            SBoxMILPInequalityStrategy.MINIMUM,
            type(self).model_provenance,
        )


class SBoxXorLinearMinimumMILPModel(_SBoxInequalityFormulation):
    """Use a Sage/GLPK minimum-cardinality facet cover for LAT classes.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "present", TrailKind.XOR_LINEAR,
        ...     SBoxMILPInequalityStrategy.MINIMUM,
        ... )
        >>> relation = SBoxXorLinearMinimumMILPModel(system)
        >>> relation.inequality_count
        39
    """

    model_provenance = _provenance(
        "SBoxXorLinearMinimumMILPModel",
        "xor_linear",
        "legacy minimum-cardinality convex-hull facet cover",
    )

    def __init__(self, system: SBoxMILPInequalitySystem) -> None:
        super().__init__(
            system,
            TrailKind.XOR_LINEAR,
            SBoxMILPInequalityStrategy.MINIMUM,
            type(self).model_provenance,
        )


class SBoxXorDifferentialEspressoMILPModel(_SBoxInequalityFormulation):
    """Use Espresso product-of-sums clauses for DDT count classes.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "aes", TrailKind.XOR_DIFFERENTIAL,
        ...     SBoxMILPInequalityStrategy.ESPRESSO,
        ... )
        >>> relation = SBoxXorDifferentialEspressoMILPModel(system)
        >>> model = relation.milp_model(input_pattern=1, output_pattern=31)
        >>> model.is_feasible(relation.witness(1, 31))
        True
    """

    model_provenance = _provenance(
        "SBoxXorDifferentialEspressoMILPModel",
        "xor_differential",
        "legacy large-S-box Espresso product of sums",
    )

    def __init__(self, system: SBoxMILPInequalitySystem) -> None:
        super().__init__(
            system,
            TrailKind.XOR_DIFFERENTIAL,
            SBoxMILPInequalityStrategy.ESPRESSO,
            type(self).model_provenance,
        )


class SBoxXorLinearEspressoMILPModel(_SBoxInequalityFormulation):
    """Use Espresso product-of-sums clauses for signed LAT classes.

    EXAMPLES::

        >>> system = load_bundled_sbox_milp_inequalities(
        ...     "aes", TrailKind.XOR_LINEAR,
        ...     SBoxMILPInequalityStrategy.ESPRESSO,
        ... )
        >>> relation = SBoxXorLinearEspressoMILPModel(system)
        >>> model = relation.milp_model(input_pattern=1, output_pattern=72)
        >>> model.is_feasible(relation.witness(1, 72))
        True
    """

    model_provenance = _provenance(
        "SBoxXorLinearEspressoMILPModel",
        "xor_linear",
        "legacy large-S-box Espresso product of sums",
    )

    def __init__(self, system: SBoxMILPInequalitySystem) -> None:
        super().__init__(
            system,
            TrailKind.XOR_LINEAR,
            SBoxMILPInequalityStrategy.ESPRESSO,
            type(self).model_provenance,
        )


def _selector(count: int) -> str:
    return f"count_{_count_token(count)}"


def _count_token(count: int) -> str:
    return f"{'negative' if count < 0 else 'positive'}_{abs(count)}"


def _point(source: int, target: int, width: int) -> tuple[int, ...]:
    return tuple((value >> bit) & 1 for value in (source, target) for bit in reversed(range(width)))


def _contains(inequality: tuple[int, ...], point: tuple[int, ...]) -> bool:
    return (
        inequality[0]
        + sum(coefficient * value for coefficient, value in zip(inequality[1:], point))
        >= 0
    )


def _espresso_excluded_points(inequality: tuple[int, ...], width: int) -> int:
    coefficients = inequality[1:]
    if any(value not in (-1, 0, 1) for value in coefficients):
        raise ValueError("Espresso clauses require coefficients in {-1, 0, 1}")
    if inequality[0] != sum(value == -1 for value in coefficients) - 1:
        raise ValueError("invalid Espresso clause constant")
    fixed = [(index, int(value == -1)) for index, value in enumerate(coefficients) if value]
    free = [index for index, value in enumerate(coefficients) if not value]
    excluded = 0
    for suffix in range(1 << len(free)):
        point = [0] * (2 * width)
        for index, value in fixed:
            point[index] = value
        for offset, index in enumerate(free):
            point[index] = (suffix >> offset) & 1
        value = 0
        for bit in point:
            value = (value << 1) | bit
        excluded |= 1 << value
    return excluded


__all__ = [
    "SBoxMILPInequalityGroup",
    "SBoxMILPInequalityStrategy",
    "SBoxMILPInequalitySystem",
    "SBoxXorDifferentialConvexHullMILPModel",
    "SBoxXorDifferentialEspressoMILPModel",
    "SBoxXorDifferentialGreedyMILPModel",
    "SBoxXorDifferentialMinimumMILPModel",
    "SBoxXorLinearConvexHullMILPModel",
    "SBoxXorLinearEspressoMILPModel",
    "SBoxXorLinearGreedyMILPModel",
    "SBoxXorLinearMinimumMILPModel",
    "load_bundled_sbox_milp_inequalities",
]
