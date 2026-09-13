import pytest

from claasp_next.representations.constraints.milp import (
    ConstraintSense, LinearConstraint, LinearExpression, LinearVariable,
    MILPModel, ObjectiveSense, VariableKind,
)
from claasp_next.drivers.solvers import GLPKSolver, MILPStatus


pytestmark = pytest.mark.external


def test_glpk_optimizes_and_returns_an_independently_checked_witness():
    model = MILPModel(
        tuple(LinearVariable(name, VariableKind.BINARY) for name in ("x", "y", "z")),
        (LinearConstraint(LinearExpression.from_terms({"x": 2, "y": 3, "z": 4}), ConstraintSense.LESS_EQUAL, 5),),
        LinearExpression.from_terms({"x": 3, "y": 4, "z": 5}),
        ObjectiveSense.MAXIMIZE,
    )
    result = GLPKSolver().solve(model)
    assert result.status is MILPStatus.OPTIMAL
    assert result.objective_value == 7
    assert model.is_feasible(result.assignment)


def test_glpk_reports_an_infeasible_model_without_a_witness():
    x = LinearVariable("x", VariableKind.BINARY)
    model = MILPModel(
        (x,),
        (
            LinearConstraint(LinearExpression.from_terms({"x": 1}), ConstraintSense.EQUAL, 0),
            LinearConstraint(LinearExpression.from_terms({"x": 1}), ConstraintSense.EQUAL, 1),
        ),
    )
    result = GLPKSolver().solve(model)
    assert result.status is MILPStatus.INFEASIBLE
    assert result.assignment is None
