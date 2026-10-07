"""Exact probability-bearing S-box component relations for MILP."""

from math import log2
from typing import ClassVar

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.milp.components.relations import (
    FiniteBinaryRelationMILPModel,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    MILPModel,
)
from claasp.semantics.cryptanalysis import SBoxTransitionSemantics, TrailKind


class SBoxTransitionMILPModel:
    """One selector per supported DDT or signed-LAT transition.

    Solver objective coefficients approximate logarithmic weights, while
    decoded transitions retain exact integer counts and correlation signs.


    EXAMPLES::

        >>> relation = SBoxTransitionMILPModel((0, 1), TrailKind.XOR_DIFFERENTIAL)
        >>> model = relation.milp_model(input_pattern=1, output_pattern=1)
        >>> tuple(variable.name for variable in model.variables[:2])
        ('input_0', 'output_0')
        >>> len(relation.relation.rows)
        2
    """

    model_provenance_by_kind: ClassVar = {
        TrailKind.XOR_DIFFERENTIAL: _direct_model(
            ConstraintBackend.MILP,
            "SBoxXorDifferentialMILPModel",
            "xor_differential",
            "one-hot exhaustive DDT row selection",
            "The finite relation is enumerated directly from the supplied S-box table.",
        ),
        TrailKind.XOR_LINEAR: _direct_model(
            ConstraintBackend.MILP,
            "SBoxXorLinearMILPModel",
            "xor_linear",
            "one-hot exhaustive LAT row selection",
            "The finite relation is enumerated directly from the supplied S-box table.",
        ),
    }

    def __init__(self, table, kind):
        if kind not in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR):
            raise ValueError("S-box MILP requires differential or linear semantics")
        self.semantics = SBoxTransitionSemantics(table)
        self.kind = kind
        self.model_provenance = self.model_provenance_by_kind[kind]
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
        self._model = MILPModel(
            model.variables,
            tuple(constraints),
            model.objective,
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
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


class SBoxXorDifferentialMILPModel(SBoxTransitionMILPModel):
    """Encode one exact S-box XOR-differential relation as MILP.

    EXAMPLES::

        >>> relation = SBoxXorDifferentialMILPModel((0, 1))
        >>> relation.kind is TrailKind.XOR_DIFFERENTIAL
        True
        >>> len(relation.relation.rows)
        2
    """

    model_provenance = SBoxTransitionMILPModel.model_provenance_by_kind[TrailKind.XOR_DIFFERENTIAL]

    def __init__(self, table) -> None:
        super().__init__(table, TrailKind.XOR_DIFFERENTIAL)
        self.model_provenance = type(self).model_provenance


class SBoxXorLinearMILPModel(SBoxTransitionMILPModel):
    """Encode one exact S-box XOR-linear relation as MILP.

    EXAMPLES::

        >>> relation = SBoxXorLinearMILPModel((0, 1))
        >>> relation.kind is TrailKind.XOR_LINEAR
        True
        >>> len(relation.relation.rows)
        2
    """

    model_provenance = SBoxTransitionMILPModel.model_provenance_by_kind[TrailKind.XOR_LINEAR]

    def __init__(self, table) -> None:
        super().__init__(table, TrailKind.XOR_LINEAR)
        self.model_provenance = type(self).model_provenance
