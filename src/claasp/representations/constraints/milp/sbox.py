"""Exact probability-bearing S-box relations with an open MILP baseline."""

from math import log2

from claasp.semantics.cryptanalysis import SBoxTransitionSemantics, TrailKind

from .model import ConstraintSense, LinearConstraint, LinearExpression, MILPModel
from .relations import FiniteBinaryRelationMILPModel


class SBoxTransitionMILPModel:
    """One selector per supported DDT or signed-LAT transition.

    Solver objective coefficients approximate logarithmic weights, while
    decoded transitions retain exact integer counts and correlation signs.


    EXAMPLES::

        >>> try:
        ...     SBoxTransitionMILPModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, table, kind):
        if kind not in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR):
            raise ValueError("S-box MILP requires differential or linear semantics")
        self.semantics = SBoxTransitionSemantics(table)
        self.kind = kind
        self.columns = tuple(
            f"{prefix}_{bit}"
            for prefix in ("input", "output")
            for bit in range(self.semantics.width)
        )
        rows, costs = [], []
        counts = (
            self.semantics.difference_distribution_table()
            if kind is TrailKind.XOR_DIFFERENTIAL
            else self.semantics.walsh_correlation_table()
        )
        for source in range(len(self.semantics.table)):
            for target in range(len(self.semantics.table)):
                count = counts[source][target]
                if count:
                    rows.append(
                        tuple(
                            (value >> bit) & 1
                            for value in (source, target)
                            for bit in reversed(range(self.semantics.width))
                        )
                    )
                    costs.append(log2(len(self.semantics.table) / abs(count)))
        self.relation = FiniteBinaryRelationMILPModel(self.columns, rows, row_costs=costs)
        self._model = None

    def _transition(self, source, target):
        return (
            self.semantics.xor_differential(source, target)
            if self.kind is TrailKind.XOR_DIFFERENTIAL
            else self.semantics.xor_linear(source, target)
        )

    def milp_model(self, *, input_pattern=None, output_pattern=None):
        """Compute the milp model for this public typed contract."""

        model = self.relation.milp_model()
        constraints = list(model.constraints)
        width = self.semantics.width
        for prefix, value in (("input", input_pattern), ("output", output_pattern)):
            if value is not None:
                self.semantics._validate_pattern(value)
                for bit in range(width):
                    constraints.append(
                        LinearConstraint(
                            LinearExpression.from_terms({f"{prefix}_{bit}": 1}),
                            ConstraintSense.EQUAL,
                            (value >> (width - 1 - bit)) & 1,
                            f"fixed_{prefix}_{bit}",
                        )
                    )
        self._model = MILPModel(model.variables, tuple(constraints), model.objective)
        return self._model

    def decode_transition(self, assignment):
        """Compute the decode transition for this public typed contract."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        if not self._model.is_feasible(assignment):
            raise ValueError("invalid S-box MILP witness")
        values = []
        for prefix in ("input", "output"):
            value = 0
            for bit in range(self.semantics.width):
                value = (value << 1) | round(assignment[f"{prefix}_{bit}"])
            values.append(value)
        transition = self._transition(*values)
        if (
            not transition.is_possible
            or abs(self._model.objective_value(assignment) - transition.weight) > 1e-7
        ):
            raise ValueError("S-box MILP objective disagrees with exact transition")
        return transition
