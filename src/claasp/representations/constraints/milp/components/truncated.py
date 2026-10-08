"""MILP encodings for local truncated-difference relations."""

from dataclasses import dataclass

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
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
from claasp.semantics.cryptanalysis import WordwiseDifferenceKind, WordwiseXorDifference


@dataclass(frozen=True, slots=True)
class WordwiseImpossibleBoundaryResult:
    """Decoded four-state word boundaries and selected contradictions.

    EXAMPLES::

        >>> result = WordwiseImpossibleBoundaryResult((0, 2), (2, 0), (1,))
        >>> result.contradictory_positions
        (1,)
    """

    forward: tuple[int, ...]
    backward: tuple[int, ...]
    contradictory_positions: tuple[int, ...]


class WordwiseImpossibleBoundaryMILPModel:
    """Select legacy four-state wordwise incompatibilities exactly.

    The recovered relation recognizes only ``(0,1)``, ``(0,2)``, ``(1,0)``,
    and ``(2,0)`` as contradictory. State 3 is unrestricted/unknown and does
    not prove impossibility. ``?`` leaves a boundary word solver-selected.

    EXAMPLES::

        >>> model = WordwiseImpossibleBoundaryMILPModel("20", "00")
        >>> formulation = model.milp_model()
        >>> (len(formulation.variables), formulation.constraints[-1].name)
        (26, 'wordwise_contradiction_exists')
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "WordwiseImpossibleBoundaryMILPModel",
        "wordwise_impossible_xor_differential",
        "legacy four-state middle incompatibility selector",
        "The local relation is exact; complete graph composition is exposed by the trail model.",
    )

    _INCOMPATIBLE = ((0, 1), (0, 2), (1, 0), (2, 0))

    def __init__(self, forward_pattern: str, backward_pattern: str, *, exactly_one=True):
        if (
            not isinstance(forward_pattern, str)
            or not isinstance(backward_pattern, str)
            or not forward_pattern
            or len(forward_pattern) != len(backward_pattern)
            or set(forward_pattern + backward_pattern) - set("0123?")
        ):
            raise ValueError("wordwise patterns must be equal-length strings over 0,1,2,3,?")
        if not isinstance(exactly_one, bool):
            raise TypeError("exactly_one must be a boolean")
        self.forward_pattern = forward_pattern
        self.backward_pattern = backward_pattern
        self.exactly_one = exactly_one
        self._model: MILPModel | None = None

    @staticmethod
    def _state_name(side, position, state):
        return f"{side}_{position}_state_{state}"

    def milp_model(self) -> MILPModel:
        """Return the complete one-hot boundary and incompatibility model."""

        variables = []
        constraints = []
        for position in range(len(self.forward_pattern)):
            for side in ("forward", "backward"):
                names = tuple(self._state_name(side, position, state) for state in range(4))
                variables.extend(LinearVariable(name, VariableKind.BINARY) for name in names)
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms(dict.fromkeys(names, 1)),
                        ConstraintSense.EQUAL,
                        1,
                        f"{side}_{position}_one_hot",
                    )
                )
            indicator = f"inconsistent_{position}"
            variables.append(LinearVariable(indicator, VariableKind.BINARY))
            pair_names = []
            for forward_state, backward_state in self._INCOMPATIBLE:
                pair = f"pair_{position}_{forward_state}_{backward_state}"
                pair_names.append(pair)
                variables.append(LinearVariable(pair, VariableKind.BINARY))
                forward = self._state_name("forward", position, forward_state)
                backward = self._state_name("backward", position, backward_state)
                constraints.extend(
                    (
                        LinearConstraint(
                            LinearExpression.from_terms({pair: 1, forward: -1}),
                            ConstraintSense.LESS_EQUAL,
                            0,
                            f"{pair}_forward",
                        ),
                        LinearConstraint(
                            LinearExpression.from_terms({pair: 1, backward: -1}),
                            ConstraintSense.LESS_EQUAL,
                            0,
                            f"{pair}_backward",
                        ),
                    )
                )
            constraints.append(
                LinearConstraint(
                    LinearExpression.from_terms(
                        {indicator: 1, **{name: -1 for name in pair_names}}
                    ),
                    ConstraintSense.EQUAL,
                    0,
                    f"inconsistent_{position}_definition",
                )
            )
        for side, pattern in (
            ("forward", self.forward_pattern),
            ("backward", self.backward_pattern),
        ):
            for position, symbol in enumerate(pattern):
                if symbol != "?":
                    constraints.append(
                        LinearConstraint(
                            LinearExpression.from_terms(
                                {self._state_name(side, position, int(symbol)): 1}
                            ),
                            ConstraintSense.EQUAL,
                            1,
                            f"fix_{side}_{position}",
                        )
                    )
        indicators = {
            f"inconsistent_{position}": 1 for position in range(len(self.forward_pattern))
        }
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms(indicators),
                ConstraintSense.EQUAL if self.exactly_one else ConstraintSense.GREATER_EQUAL,
                1,
                "wordwise_contradiction_exists",
            )
        )
        unknowns = {
            self._state_name("forward", position, WordwiseDifferenceKind.UNKNOWN.value): 1
            for position in range(len(self.forward_pattern))
        }
        self._model = MILPModel(
            tuple(variables),
            tuple(constraints),
            LinearExpression.from_terms(unknowns),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_boundary(self, assignment) -> WordwiseImpossibleBoundaryResult:
        """Decode a feasible assignment and independently verify each selector."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        values = {name: int(round(value)) for name, value in assignment.items()}
        if not self._model.is_feasible(values):
            raise ValueError("invalid wordwise impossible-boundary assignment")

        def states(side):
            return tuple(
                next(state for state in range(4) if values[self._state_name(side, position, state)])
                for position in range(len(self.forward_pattern))
            )

        forward, backward = states("forward"), states("backward")
        selected = tuple(
            position for position in range(len(forward)) if values[f"inconsistent_{position}"]
        )
        if any(
            (forward[position], backward[position]) not in self._INCOMPATIBLE
            for position in selected
        ):
            raise ValueError("wordwise incompatibility selector chose a compatible state pair")
        return WordwiseImpossibleBoundaryResult(forward, backward, selected)


def wordwise_pattern(differences) -> str:
    """Encode typed wordwise differences as legacy four-state digits.

    EXAMPLES::

        >>> zero = WordwiseXorDifference(4, WordwiseDifferenceKind.ZERO)
        >>> nonzero = WordwiseXorDifference(4, WordwiseDifferenceKind.NONZERO)
        >>> wordwise_pattern((zero, nonzero))
        '02'
    """

    values = tuple(differences)
    if not values or any(not isinstance(item, WordwiseXorDifference) for item in values):
        raise TypeError("differences must contain typed wordwise XOR differences")
    return "".join(str(item.kind.value) for item in values)
