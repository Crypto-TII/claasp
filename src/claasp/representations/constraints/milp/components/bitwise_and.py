"""MILP encodings for two-input bitwise-AND trail relations."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _unaudited_model,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)
from claasp.semantics.cryptanalysis import BitwiseAndSemantics, TrailKind

_DIFFERENTIAL_ROWS = (
    (0, 0, 0, 0),
    (0, 1, 0, 1),
    (0, 1, 1, 1),
    (1, 0, 0, 1),
    (1, 0, 1, 1),
    (1, 1, 0, 1),
    (1, 1, 1, 1),
)
_LINEAR_ROWS = ((0, 0, 0), (0, 0, 1), (0, 1, 1), (1, 0, 1), (1, 1, 1))


def _constraint(terms, sense, rhs, name=None):
    return LinearConstraint(LinearExpression.from_terms(terms), sense, rhs, name)


class BitwiseAndOneHotMILPModel:
    """Encode each one-bit AND transition with an exhaustive row selector.

    This portable formulation is the comparison baseline for compact recovered
    inequalities. It makes no convex-hull or minimum-size claim.

    EXAMPLES::

        >>> model = BitwiseAndOneHotMILPModel(2, TrailKind.XOR_DIFFERENTIAL)
        >>> formulation = model.milp_model(left_pattern=1, right_pattern=0, output_pattern=1)
        >>> (len(formulation.variables), len(formulation.constraints))
        (22, 16)
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "BitwiseAndOneHotMILPModel",
        "xor_differential_or_linear",
        "one-hot exhaustive one-bit AND relation",
        "Every supported DDT or LAT row is selected directly.",
    )

    def __init__(self, width: int, kind: TrailKind) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise ValueError("width must be a positive integer")
        if kind not in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR):
            raise ValueError("kind must be XOR differential or XOR linear")
        self.width = width
        self.kind = kind
        self._groups: tuple[tuple[str, ...], ...] = ()

    def milp_model(
        self, *, left_pattern=None, right_pattern=None, output_pattern=None
    ) -> MILPModel:
        """Return a fixed or free one-hot AND transition model."""

        self._validate_patterns(left_pattern, right_pattern, output_pattern)
        variables: list[LinearVariable] = []
        constraints: list[LinearConstraint] = []

        def binary(name):
            variables.append(LinearVariable(name, VariableKind.BINARY))
            return name

        left = tuple(binary(f"left_{bit}") for bit in range(self.width))
        right = tuple(binary(f"right_{bit}") for bit in range(self.width))
        output = tuple(binary(f"output_{bit}") for bit in range(self.width))
        weight = (
            tuple(binary(f"weight_{bit}") for bit in range(self.width))
            if self.kind is TrailKind.XOR_DIFFERENTIAL
            else output
        )
        rows = _DIFFERENTIAL_ROWS if self.kind is TrailKind.XOR_DIFFERENTIAL else _LINEAR_ROWS
        columns = (left, right, output, weight) if len(rows[0]) == 4 else (left, right, output)
        for bit in range(self.width):
            selectors = tuple(binary(f"row_{bit}_{row}") for row in range(len(rows)))
            constraints.append(
                _constraint(
                    dict.fromkeys(selectors, 1),
                    ConstraintSense.EQUAL,
                    1,
                    f"and_select_{bit}",
                )
            )
            for position, group in enumerate(columns):
                terms = {group[bit]: 1}
                terms.update(
                    {
                        selector: -row[position]
                        for selector, row in zip(selectors, rows)
                        if row[position]
                    }
                )
                constraints.append(
                    _constraint(
                        terms,
                        ConstraintSense.EQUAL,
                        0,
                        f"and_column_{bit}_{position}",
                    )
                )
        self._fix(constraints, left, left_pattern, "left")
        self._fix(constraints, right, right_pattern, "right")
        self._fix(constraints, output, output_pattern, "output")
        self._groups = left, right, output
        return MILPModel(
            tuple(variables),
            tuple(constraints),
            LinearExpression.from_terms(dict.fromkeys(weight, 1)),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )

    def _validate_patterns(self, *patterns):
        for value in patterns:
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value < 1 << self.width
            ):
                raise ValueError("patterns must fit the configured width")

    def _fix(self, constraints, names, value, prefix):
        if value is None:
            return
        for bit, name in enumerate(names):
            constraints.append(
                _constraint(
                    {name: 1},
                    ConstraintSense.EQUAL,
                    (value >> (self.width - 1 - bit)) & 1,
                    f"fixed_{prefix}_{bit}",
                )
            )

    def decode_transition(self, assignment):
        """Decode and independently validate the selected AND transition."""

        if not self._groups:
            raise ValueError("build the MILP model before decoding a transition")
        left, right, output = (
            sum(round(assignment[name]) << (self.width - 1 - bit) for bit, name in enumerate(group))
            for group in self._groups
        )
        semantics = BitwiseAndSemantics(self.width)
        transition = (
            semantics.xor_differential(left, right, output)
            if self.kind is TrailKind.XOR_DIFFERENTIAL
            else semantics.xor_linear(left, right, output)
        )
        if not transition.is_possible:
            raise ValueError("assignment describes an impossible AND transition")
        return transition


class _BitwiseAndReducedMILPModel(BitwiseAndOneHotMILPModel):
    def milp_model(
        self, *, left_pattern=None, right_pattern=None, output_pattern=None
    ) -> MILPModel:
        self._validate_patterns(left_pattern, right_pattern, output_pattern)
        variables: list[LinearVariable] = []
        constraints: list[LinearConstraint] = []

        def binary(name):
            variables.append(LinearVariable(name, VariableKind.BINARY))
            return name

        left = tuple(binary(f"left_{bit}") for bit in range(self.width))
        right = tuple(binary(f"right_{bit}") for bit in range(self.width))
        output = tuple(binary(f"output_{bit}") for bit in range(self.width))
        if self.kind is TrailKind.XOR_DIFFERENTIAL:
            weight = tuple(binary(f"weight_{bit}") for bit in range(self.width))
            for bit in range(self.width):
                constraints.extend(
                    (
                        _constraint(
                            {weight[bit]: 1, left[bit]: -1}, ConstraintSense.GREATER_EQUAL, 0
                        ),
                        _constraint(
                            {weight[bit]: 1, right[bit]: -1}, ConstraintSense.GREATER_EQUAL, 0
                        ),
                        _constraint(
                            {left[bit]: 1, right[bit]: 1, weight[bit]: -1},
                            ConstraintSense.GREATER_EQUAL,
                            0,
                        ),
                        _constraint(
                            {weight[bit]: 1, output[bit]: -1},
                            ConstraintSense.GREATER_EQUAL,
                            0,
                        ),
                    )
                )
        else:
            weight = output
            for bit in range(self.width):
                constraints.extend(
                    (
                        _constraint(
                            {output[bit]: 1, left[bit]: -1},
                            ConstraintSense.GREATER_EQUAL,
                            0,
                        ),
                        _constraint(
                            {output[bit]: 1, right[bit]: -1},
                            ConstraintSense.GREATER_EQUAL,
                            0,
                        ),
                    )
                )
        self._fix(constraints, left, left_pattern, "left")
        self._fix(constraints, right, right_pattern, "right")
        self._fix(constraints, output, output_pattern, "output")
        self._groups = left, right, output
        return MILPModel(
            tuple(variables),
            tuple(constraints),
            LinearExpression.from_terms(dict.fromkeys(weight, 1)),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )


class BitwiseAndXorDifferentialMILPModel(_BitwiseAndReducedMILPModel):
    """Recover the four legacy reduced inequalities per AND output bit.

    EXAMPLES::

        >>> model = BitwiseAndXorDifferentialMILPModel(2)
        >>> formulation = model.milp_model(left_pattern=1, right_pattern=0, output_pattern=1)
        >>> (len(formulation.variables), len(formulation.constraints), len(formulation.objective.terms))
        (8, 14, 2)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "BitwiseAndXorDifferentialMILPModel",
        "xor_differential",
        "legacy greedy reduced AND inequalities",
        "Primary-source correspondence remains to be audited.",
    )

    def __init__(self, width: int) -> None:
        super().__init__(width, TrailKind.XOR_DIFFERENTIAL)


class BitwiseAndXorLinearMILPModel(_BitwiseAndReducedMILPModel):
    """Recover the two legacy reduced XOR-linear inequalities per AND bit.

    EXAMPLES::

        >>> model = BitwiseAndXorLinearMILPModel(2)
        >>> formulation = model.milp_model(left_pattern=1, right_pattern=0, output_pattern=1)
        >>> (len(formulation.variables), len(formulation.constraints), len(formulation.objective.terms))
        (6, 10, 2)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "BitwiseAndXorLinearMILPModel",
        "xor_linear",
        "legacy greedy reduced AND LAT inequalities",
        "Primary-source correspondence remains to be audited.",
    )

    def __init__(self, width: int) -> None:
        super().__init__(width, TrailKind.XOR_LINEAR)


__all__ = [
    "BitwiseAndOneHotMILPModel",
    "BitwiseAndXorDifferentialMILPModel",
    "BitwiseAndXorLinearMILPModel",
]
