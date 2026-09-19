"""Exact binary-linear lowering of solver-independent Boolean clauses."""

from claasp_next.representations.constraints.sat import BooleanCNFModel, CNFFormula

from .model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    VariableKind,
)


def cnf_to_milp(formula):
    """Translate each clause to the exact inequality ``sum(literals) >= 1``.

    A positive literal is ``x``; a negative literal is ``1-x``. Repeated
    variables are combined, including tautological positive/negative pairs.
    No convex-hull package, Sage, or proprietary solver is needed.


    EXAMPLES::

        >>> try:
        ...     cnf_to_milp()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """
    if not isinstance(formula, CNFFormula):
        raise TypeError("formula must be a CNFFormula")
    constraints = []
    for number, clause in enumerate(formula.clauses):
        terms, negative = {}, 0
        for literal in clause:
            name = formula.variables[abs(literal) - 1]
            terms[name] = terms.get(name, 0) + (1 if literal > 0 else -1)
            negative += literal < 0
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms(terms),
                ConstraintSense.GREATER_EQUAL,
                1 - negative,
                f"clause_{number}",
            )
        )
    return MILPModel(
        tuple(LinearVariable(name, VariableKind.BINARY) for name in formula.variables),
        tuple(constraints),
    )


class BooleanGraphMILPModel:
    """Exact Bit/Word graph execution, not a differential propagation model.

    EXAMPLES::

        >>> try:
        ...     BooleanGraphMILPModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive):
        self.boolean_model = BooleanCNFModel(primitive)

    def milp_model(self):
        """Compute the milp model for this public typed contract."""

        return cnf_to_milp(self.boolean_model.cnf_formula())

    def witness(self, evaluation):
        """Derive every binary auxiliary from independent scalar execution."""
        return self.boolean_model.witness(evaluation)
