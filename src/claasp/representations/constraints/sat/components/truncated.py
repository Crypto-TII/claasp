"""SAT relations for truncated and impossible propagation boundaries."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _unaudited_model,
)
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.semantics.cryptanalysis import (
    ImpossiblePropagationBoundary,
    ProbabilisticTruncatedModularAddTransition,
    TruncatedBit,
    TruncatedXorDifference,
    check_probabilistic_truncated_modular_add,
)

_COSTS = (0, 4, 9, 19, 41, 100)


class ProbabilisticTruncatedModularAddSATModel:
    """Encode the legacy counter-based partial-addition relation in CNF.

    Every truncated bit uses the canonical ``(unknown, value)`` pair. Carry
    differences, zero-run lengths, and the fixed-point costs are explicit, so
    a solver witness can be projected to the same typed transition as the CP
    model and checked independently.

    EXAMPLES::

        >>> model = ProbabilisticTruncatedModularAddSATModel(
        ...     2, left_pattern="00", right_pattern="00", output_pattern="00"
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count, "probabilistic_truncated_cost" in formula.provenance)
        (33, True)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SAT,
        "ProbabilisticTruncatedModularAddSATModel",
        "probabilistic_truncated_xor",
        "counter-based partial-addition relation in ordinary CNF",
        "The exact correspondence with a primary-source construction has not been audited.",
    )

    def __init__(
        self,
        width: int,
        *,
        left_pattern=None,
        right_pattern=None,
        output_pattern=None,
        carry_pattern=None,
    ) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise ValueError("width must be a positive integer")
        self.width = width
        self.left_pattern = self._coerce(left_pattern)
        self.right_pattern = self._coerce(right_pattern)
        self.output_pattern = self._coerce(output_pattern)
        self.carry_pattern = self._coerce(carry_pattern)
        self._formula: CNFFormula | None = None

    def _coerce(self, pattern):
        if pattern is None:
            return None
        if isinstance(pattern, str):
            pattern = TruncatedXorDifference.parse(pattern)
        if not isinstance(pattern, TruncatedXorDifference):
            raise TypeError("patterns must be strings or TruncatedXorDifference values")
        if len(pattern.bits) != self.width:
            raise ValueError(f"patterns must contain {self.width} bits")
        return pattern

    @staticmethod
    def _encoded(bit):
        return (1, 0) if bit is TruncatedBit.UNKNOWN else (0, int(bit.value))

    def cnf_formula(self) -> CNFFormula:
        """Return the exact finite counter-based relation as ordinary CNF."""

        variables: list[str] = []
        indices: dict[str, int] = {}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []

        def allocate(name):
            variables.append(name)
            indices[name] = len(variables)
            return name

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        names = {
            prefix: tuple(
                (allocate(f"{prefix}_{bit}_unknown"), allocate(f"{prefix}_{bit}_value"))
                for bit in range(self.width)
            )
            for prefix in ("left", "right", "output", "carry")
        }
        for pairs in names.values():
            for unknown, value in pairs:
                add((-indices[unknown], -indices[value]), "truncated_canonical_unknown")

        runs = tuple(
            tuple(allocate(f"run_{bit}_{length}") for length in range(self.width))
            for bit in range(self.width)
        )
        costs = tuple(
            tuple(allocate(f"cost_{bit}_{cost}") for cost in _COSTS) for bit in range(self.width)
        )

        def exactly_one(group, label):
            add((indices[name] for name in group), label)
            for left in range(len(group)):
                for right in range(left + 1, len(group)):
                    add((-indices[group[left]], -indices[group[right]]), label)

        for group in (*runs, *costs):
            exactly_one(group, "probabilistic_truncated_one_hot")

        symbols = (TruncatedBit.ZERO, TruncatedBit.ONE, TruncatedBit.UNKNOWN)

        def mismatch(pair, bit):
            return tuple(
                -indices[name] if value else indices[name]
                for name, value in zip(pair, self._encoded(bit))
            )

        for bit in range(self.width):
            for left in symbols:
                for right in symbols:
                    for carry in symbols:
                        expected = (
                            TruncatedBit.UNKNOWN
                            if TruncatedBit.UNKNOWN in (left, right, carry)
                            else TruncatedBit.ONE
                            if sum(int(item.value) for item in (left, right, carry)) % 2
                            else TruncatedBit.ZERO
                        )
                        for output in symbols:
                            if output is expected:
                                continue
                            add(
                                mismatch(names["left"][bit], left)
                                + mismatch(names["right"][bit], right)
                                + mismatch(names["carry"][bit], carry)
                                + mismatch(names["output"][bit], output),
                                "probabilistic_truncated_output",
                            )

        last = self.width - 1
        for name, value in zip(names["carry"][last], self._encoded(TruncatedBit.ZERO)):
            add(((indices[name] if value else -indices[name]),), "probabilistic_truncated_lsb")
        add((indices[costs[last][0]],), "probabilistic_truncated_lsb")
        add((indices[runs[last][0]],), "probabilistic_truncated_lsb")

        for bit in range(last):
            condition = allocate(f"zero_run_condition_{bit}")
            desired = (
                -indices[names["left"][bit + 1][0]],
                -indices[names["left"][bit + 1][1]],
                -indices[names["right"][bit + 1][0]],
                -indices[names["right"][bit + 1][1]],
                indices[names["carry"][bit + 1][0]],
            )
            for literal in desired:
                add((-indices[condition], literal), "probabilistic_truncated_zero_run")
            add(
                (indices[condition], *(-literal for literal in desired)),
                "probabilistic_truncated_zero_run",
            )
            add((indices[condition], indices[runs[bit][0]]), "probabilistic_truncated_zero_run")
            for length in range(self.width - 1):
                add(
                    (
                        -indices[condition],
                        -indices[runs[bit + 1][length]],
                        indices[runs[bit][length + 1]],
                    ),
                    "probabilistic_truncated_zero_run",
                )
            add(
                (-indices[condition], -indices[runs[bit + 1][-1]]),
                "probabilistic_truncated_zero_run",
            )

            for left in symbols:
                for right in symbols:
                    for output in symbols:
                        fixed = (left, right, output)
                        for run_length in range(self.width):
                            if fixed == (TruncatedBit.ZERO,) * 3:
                                allowed = {(TruncatedBit.ZERO, 0)}
                            elif fixed == (TruncatedBit.ONE,) * 3:
                                allowed = {(TruncatedBit.ONE, 0)}
                            else:
                                allowed = {(TruncatedBit.UNKNOWN, 0)}
                                if run_length == 0:
                                    allowed.update(
                                        ((TruncatedBit.ZERO, 100), (TruncatedBit.ONE, 100))
                                    )
                                elif run_length <= 4:
                                    allowed.add(
                                        (
                                            TruncatedBit.ZERO,
                                            {1: 41, 2: 19, 3: 9, 4: 4}[run_length],
                                        )
                                    )
                                else:
                                    allowed.add((TruncatedBit.ZERO, 0))
                            antecedent = (
                                mismatch(names["left"][bit + 1], left)
                                + mismatch(names["right"][bit + 1], right)
                                + mismatch(names["output"][bit + 1], output)
                                + (-indices[runs[bit][run_length]],)
                            )
                            for carry in symbols:
                                for cost_number, cost in enumerate(_COSTS):
                                    if (carry, cost) in allowed:
                                        continue
                                    add(
                                        antecedent
                                        + mismatch(names["carry"][bit], carry)
                                        + (-indices[costs[bit][cost_number]],),
                                        "probabilistic_truncated_cost",
                                    )

        for prefix, pattern in (
            ("left", self.left_pattern),
            ("right", self.right_pattern),
            ("output", self.output_pattern),
            ("carry", self.carry_pattern),
        ):
            if pattern is None:
                continue
            for pair, value in zip(names[prefix], pattern.bits):
                for name, encoded in zip(pair, self._encoded(value)):
                    add(
                        ((indices[name] if encoded else -indices[name]),),
                        f"fixed_{prefix}",
                    )

        self._formula = CNFFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def decode_transition(self, assignment) -> ProbabilisticTruncatedModularAddTransition:
        """Decode and independently validate one complete SAT assignment."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid probabilistic truncated SAT witness")

        def pattern(prefix):
            return TruncatedXorDifference(
                tuple(
                    TruncatedBit.UNKNOWN
                    if assignment[f"{prefix}_{bit}_unknown"]
                    else TruncatedBit.ONE
                    if assignment[f"{prefix}_{bit}_value"]
                    else TruncatedBit.ZERO
                    for bit in range(self.width)
                )
            )

        transition = ProbabilisticTruncatedModularAddTransition(
            pattern("left"),
            pattern("right"),
            pattern("output"),
            pattern("carry"),
            tuple(
                next(cost for cost in _COSTS if assignment[f"cost_{bit}_{cost}"])
                for bit in range(self.width)
            ),
        )
        if not check_probabilistic_truncated_modular_add(transition):
            raise ValueError("SAT witness violates the counter-based partial-addition relation")
        return transition


class ImpossibleBoundarySATModel:
    """Encode fixed-bit contradictions between two truncated boundaries.

    One indicator is true exactly when both directional bits are known and
    opposite. By default the formula requires at least one such indicator.
    Unknown trits retain the legacy redundant value bit, which is ignored by
    decoding and by the incompatibility relation.

    EXAMPLES::

        >>> model = ImpossibleBoundarySATModel(
        ...     3, forward_pattern="01?", backward_pattern="00?"
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count, formula.clause_count)
        (15, 31)
        >>> formula.variables[-3:]
        ('incompatibility_0', 'incompatibility_1', 'incompatibility_2')
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ImpossibleBoundarySATModel",
        "impossible_xor_differential",
        "legacy six-clause fixed-bit incompatibility indicators",
        "Each indicator is equivalent to two known, opposite truncated bits.",
    )

    def __init__(
        self,
        width: int,
        *,
        forward_pattern=None,
        backward_pattern=None,
        require_incompatibility: bool = True,
    ) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise ValueError("width must be a positive integer")
        if not isinstance(require_incompatibility, bool):
            raise TypeError("require_incompatibility must be Boolean")
        self.width = width
        self.forward_pattern = self._coerce(forward_pattern)
        self.backward_pattern = self._coerce(backward_pattern)
        self.require_incompatibility = require_incompatibility

    def _coerce(self, pattern):
        if pattern is None:
            return None
        if isinstance(pattern, str):
            pattern = TruncatedXorDifference.parse(pattern)
        if not isinstance(pattern, TruncatedXorDifference):
            raise TypeError("boundary patterns must be strings or TruncatedXorDifference values")
        if len(pattern.bits) != self.width:
            raise ValueError(f"boundary patterns must contain {self.width} bits")
        return pattern

    @staticmethod
    def _encoded(bit):
        return (1, 0) if bit is TruncatedBit.UNKNOWN else (0, int(bit.value))

    def cnf_formula(self) -> CNFFormula:
        """Return the exact legacy incompatibility clauses and boundary units."""

        boundary_variables = tuple(
            f"{direction}_{bit}_{field}"
            for direction in ("forward", "backward")
            for bit in range(self.width)
            for field in ("unknown", "value")
        )
        indicators = tuple(f"incompatibility_{bit}" for bit in range(self.width))
        variables = boundary_variables + indicators
        indices = {name: index for index, name in enumerate(variables, 1)}
        clauses = []
        provenance = []

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        for bit, indicator in enumerate(indicators):
            forward_unknown = indices[f"forward_{bit}_unknown"]
            forward_value = indices[f"forward_{bit}_value"]
            backward_unknown = indices[f"backward_{bit}_unknown"]
            backward_value = indices[f"backward_{bit}_value"]
            incompatible = indices[indicator]
            for clause in (
                (-forward_unknown, -incompatible),
                (-backward_unknown, -incompatible),
                (forward_value, backward_value, -incompatible),
                (-forward_value, -backward_value, -incompatible),
                (
                    forward_unknown,
                    forward_value,
                    backward_unknown,
                    incompatible,
                    -backward_value,
                ),
                (
                    forward_unknown,
                    backward_unknown,
                    backward_value,
                    incompatible,
                    -forward_value,
                ),
            ):
                add(clause, "truncated_incompatibility_indicator")
        if self.require_incompatibility:
            add((indices[name] for name in indicators), "truncated_incompatibility_exists")

        for direction, pattern in (
            ("forward", self.forward_pattern),
            ("backward", self.backward_pattern),
        ):
            if pattern is None:
                continue
            for bit, trit in enumerate(pattern.bits):
                for field, value in zip(("unknown", "value"), self._encoded(trit)):
                    name = f"{direction}_{bit}_{field}"
                    add(((indices[name] if value else -indices[name]),), f"fixed_{direction}")

        return CNFFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )

    def decode_boundary(self, assignment) -> ImpossiblePropagationBoundary:
        """Decode and independently validate all incompatibility indicators."""

        formula = self.cnf_formula()
        if not formula.is_satisfied(assignment):
            raise ValueError("invalid impossible-boundary SAT witness")

        def pattern(direction):
            return TruncatedXorDifference(
                tuple(
                    TruncatedBit.UNKNOWN
                    if assignment[f"{direction}_{bit}_unknown"]
                    else TruncatedBit.ONE
                    if assignment[f"{direction}_{bit}_value"]
                    else TruncatedBit.ZERO
                    for bit in range(self.width)
                )
            )

        boundary = ImpossiblePropagationBoundary(pattern("forward"), pattern("backward"))
        encoded_positions = tuple(
            bit for bit in range(self.width) if assignment[f"incompatibility_{bit}"]
        )
        if encoded_positions != boundary.contradictory_positions:
            raise ValueError("SAT indicators disagree with the typed impossible boundary")
        if self.require_incompatibility and not boundary.is_impossible:
            raise ValueError("decoded boundary is compatible")
        if self.forward_pattern is not None and boundary.forward != self.forward_pattern:
            raise ValueError("SAT witness changed the fixed forward boundary")
        if self.backward_pattern is not None and boundary.backward != self.backward_pattern:
            raise ValueError("SAT witness changed the fixed backward boundary")
        return boundary


__all__ = ["ImpossibleBoundarySATModel", "ProbabilisticTruncatedModularAddSATModel"]
