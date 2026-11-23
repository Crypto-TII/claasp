"""Exercise newly registered solver drivers against real executables."""

import shutil

import pytest

from claasp.drivers.solvers import (
    CadicalSolver,
    CbcSolver,
    GlucoseSolver,
    GlucoseSyrupSolver,
    MathSatSolver,
    MILPStatus,
    MiniZincSolver,
    ParKissatSolver,
    SatStatus,
    ScipSolver,
    SoplexSolver,
    YicesSatSolver,
    YicesSolver,
)
from claasp.primitives import ToySpeck
from claasp.representations.constraints.milp import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)
from claasp.representations.constraints.sat import CNFFormula
from claasp.representations.constraints.smt.formula import SMTFormula

pytestmark = pytest.mark.external


def _require(executable):
    if shutil.which(executable) is None:
        pytest.skip(f"{executable} is not installed")


SAT = CNFFormula(("x", "y"), ((1,), (2,)), ("x", "y"))
UNSAT = CNFFormula(("x",), ((1,), (-1,)), ("positive", "negative"))


@pytest.mark.parametrize(
    "solver_type",
    (CadicalSolver, GlucoseSolver, GlucoseSyrupSolver, ParKissatSolver, YicesSatSolver),
)
def test_dimacs_drivers_prove_sat_and_unsat(solver_type):
    solver = solver_type(timeout_seconds=15)
    _require(solver.executable)
    satisfied = solver.solve(SAT)
    assert satisfied.status is SatStatus.SATISFIABLE
    assert SAT.is_satisfied(satisfied.assignment or {})
    assert solver.solve(UNSAT).status is SatStatus.UNSATISFIABLE
    assert solver.solve(SAT, {"x": 0}).status is SatStatus.UNSATISFIABLE


@pytest.mark.parametrize("solver_type", (MathSatSolver, YicesSolver))
def test_smt_drivers_accept_smt_and_cnf(solver_type):
    solver = solver_type(timeout_seconds=15)
    _require(solver.executable)
    for formula in (SAT, SMTFormula.from_cnf(SAT)):
        result = solver.solve(formula)
        assert result.status is SatStatus.SATISFIABLE
        assert SAT.is_satisfied(result.assignment or {})
    assert solver.solve(UNSAT).status is SatStatus.UNSATISFIABLE


def _model(kind, *, infeasible=False):
    variables = (
        LinearVariable("x", kind, upper_bound=1),
        LinearVariable("y", kind, upper_bound=1),
    )
    constraint = LinearConstraint(
        LinearExpression.from_terms({"x": 1, "y": 1}),
        ConstraintSense.GREATER_EQUAL if infeasible else ConstraintSense.LESS_EQUAL,
        3 if infeasible else 1,
    )
    return MILPModel(
        variables,
        (constraint,),
        LinearExpression.from_terms({"x": 1, "y": 2}),
        ObjectiveSense.MAXIMIZE,
    )


@pytest.mark.parametrize("solver_type", (CbcSolver, ScipSolver))
def test_milp_drivers_optimize_and_prove_infeasibility(solver_type):
    solver = solver_type(timeout_seconds=15)
    _require(solver.executable)
    result = solver.solve(_model(VariableKind.BINARY))
    assert result.status is MILPStatus.OPTIMAL
    assert result.objective_value == 2
    assert result.assignment == {"x": 0, "y": 1}
    assert (
        solver.solve(_model(VariableKind.BINARY, infeasible=True)).status is MILPStatus.INFEASIBLE
    )
    assert solver.solve(SAT).status is SatStatus.SATISFIABLE
    assert solver.solve(UNSAT).status is SatStatus.UNSATISFIABLE


def test_soplex_solves_continuous_models_but_rejects_integrality():
    solver = SoplexSolver(timeout_seconds=15)
    _require(solver.executable)
    result = solver.solve(_model(VariableKind.CONTINUOUS))
    assert result.status is MILPStatus.OPTIMAL
    assert result.objective_value == 2
    assert (
        solver.solve(_model(VariableKind.CONTINUOUS, infeasible=True)).status
        is MILPStatus.INFEASIBLE
    )
    with pytest.raises(TypeError, match="integer variables"):
        solver.solve(_model(VariableKind.BINARY))


def test_choco_is_selectable_through_the_existing_minizinc_driver():
    _require("minizinc")
    solver = MiniZincSolver(solver="choco", timeout_seconds=15)
    result = solver.solve(SAT)
    assert result.status is SatStatus.SATISFIABLE
    assert SAT.is_satisfied(result.assignment or {})
    trail = ToySpeck(2).analysis.find_lowest_weight_xor_differential_trail(solver=solver)
    assert trail.is_optimal and trail.trail.total_weight == 0


@pytest.mark.parametrize(
    "solver_type",
    (
        CadicalSolver,
        CbcSolver,
        GlucoseSolver,
        GlucoseSyrupSolver,
        MathSatSolver,
        ParKissatSolver,
        ScipSolver,
        YicesSatSolver,
        YicesSolver,
    ),
)
def test_public_trail_search_accepts_new_boolean_drivers(solver_type):
    solver = solver_type(timeout_seconds=30)
    _require(solver.executable)
    result = ToySpeck(2).analysis.find_lowest_weight_xor_differential_trail(solver=solver)
    assert result.is_optimal
    assert result.trail.total_weight == 0
    assert result.metadata.solver == solver_type.__name__
