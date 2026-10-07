"""Exact finite binary component relations for MILP."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    VariableKind,
)


class FiniteBinaryRelationMILPModel:
    """A one-hot extended formulation retaining every accepted binary row.

    This is an exact baseline, not a minimum-facet or minimized-inequality
    claim. Row selectors are auxiliaries, not additional semantic witnesses.


    EXAMPLES::

        >>> relation = FiniteBinaryRelationMILPModel(
        ...     ("input", "output"), ((0, 0), (1, 1))
        ... )
        >>> model = relation.milp_model()
        >>> witness = relation.witness((1, 1))
        >>> model.is_feasible(witness)
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "FiniteBinaryRelationMILPModel",
        "finite_relation",
        "one-hot exhaustive row selection",
        "The relation is encoded directly from its complete set of rows.",
    )

    def __init__(self, columns, rows, *, row_costs=None):
        self.columns = tuple(columns)
        self.rows = tuple(tuple(row) for row in rows)
        if not self.columns or len(set(self.columns)) != len(self.columns):
            raise ValueError("relation columns must be nonempty and unique")
        if any(name.startswith("__relation_row_") for name in self.columns):
            raise ValueError("relation columns use a reserved auxiliary name")
        for name in self.columns:
            LinearVariable(name, VariableKind.BINARY)
        if len(set(self.rows)) != len(self.rows) or any(
            len(row) != len(self.columns) or any(value not in (0, 1) for value in row)
            for row in self.rows
        ):
            raise ValueError("relation rows must be unique binary tuples matching the columns")
        self.row_costs = tuple(0 for _ in self.rows) if row_costs is None else tuple(row_costs)
        if len(self.row_costs) != len(self.rows):
            raise ValueError("each relation row requires one objective cost")
        self.selectors = tuple(f"__relation_row_{row}" for row in range(len(self.rows)))

    def milp_model(self):
        """Compute the milp model for this public typed contract."""

        variables = tuple(
            LinearVariable(name, VariableKind.BINARY) for name in self.columns + self.selectors
        )
        constraints = []
        if not self.rows:
            for value in (0, 1):
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms({self.columns[0]: 1}),
                        ConstraintSense.EQUAL,
                        value,
                        f"empty_relation_{value}",
                    )
                )
        else:
            constraints.append(
                LinearConstraint(
                    LinearExpression.from_terms(dict.fromkeys(self.selectors, 1)),
                    ConstraintSense.EQUAL,
                    1,
                    "select_one_relation_row",
                )
            )
            for position, column in enumerate(self.columns):
                terms = {column: 1}
                terms.update(
                    {
                        selector: -row[position]
                        for selector, row in zip(self.selectors, self.rows)
                        if row[position]
                    }
                )
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms(terms),
                        ConstraintSense.EQUAL,
                        0,
                        f"relation_column_{position}",
                    )
                )
        return MILPModel(
            variables,
            tuple(constraints),
            LinearExpression.from_terms(dict(zip(self.selectors, self.row_costs))),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )

    def witness(self, row):
        """Compute the witness for this public typed contract."""

        row = tuple(row)
        if row not in self.rows:
            raise ValueError("row is not accepted by the relation")
        index = self.rows.index(row)
        return dict(zip(self.columns, row)) | {
            name: int(i == index) for i, name in enumerate(self.selectors)
        }
