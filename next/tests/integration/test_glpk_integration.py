import pytest

from claasp_next.representations.constraints.milp import (
    BooleanMonomialGraphMILPModel, ConstraintSense, LinearConstraint, LinearExpression, LinearVariable,
    MILPModel, ObjectiveSense, VariableKind,
)
from claasp_next.primitives import Simon, Speck
from claasp_next.analysis import AnalysisProblem, FixedValue
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


def test_glpk_preserves_complete_speck_execution_not_legacy_partial_model():
    primitive = Speck(number_of_rounds=22)
    problem = AnalysisProblem(primitive, (
        FixedValue(primitive.input("plaintext"), 0x6574694C),
        FixedValue(primitive.input("key"), 0x1918111009080100),
    ), {"ciphertext": primitive.output})
    result = primitive.analyze().solve(problem, GLPKSolver(timeout_seconds=10))
    assert result.is_satisfiable
    assert result.value("ciphertext") == 0xA86842F2
    assert primitive.evaluate(0x6574694C, 0x1918111009080100) == result.value("ciphertext")


@pytest.mark.parametrize("rounds, expected", ((1, 2), (2, 3), (4, 8)))
def test_glpk_recovers_exact_reduced_simon_degree_fixtures(rounds, expected):
    model = BooleanMonomialGraphMILPModel(
        Simon(number_of_rounds=rounds), 0, "plaintext"
    ).milp_model()
    result = GLPKSolver().solve(model)
    assert result.status is MILPStatus.OPTIMAL
    assert result.objective_value == expected
    assert model.is_feasible(result.assignment)


def test_glpk_preserves_legacy_simon_thirteen_cube_degree():
    model = BooleanMonomialGraphMILPModel(
        Simon(number_of_rounds=13), 16, "plaintext", range(1, 32)
    ).milp_model()
    result = GLPKSolver(timeout_seconds=30).solve(model)
    assert result.status is MILPStatus.OPTIMAL
    assert result.objective_value == 30
    assert model.is_feasible(result.assignment)
