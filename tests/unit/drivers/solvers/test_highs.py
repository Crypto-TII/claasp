"""Numerical solver results are checked before exposing portable statuses."""

from types import SimpleNamespace

import pytest

from claasp.drivers.solvers import HighsSolver, MILPStatus
from claasp.representations.constraints.milp import (
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)

scipy = pytest.importorskip("scipy.optimize")


def _model():
    return MILPModel(
        (LinearVariable("x", VariableKind.INTEGER, 0, 3),),
        (),
        LinearExpression((("x", 2),), 7),
        ObjectiveSense.MAXIMIZE,
    )


def test_maximization_and_objective_offset_are_preserved():
    result = HighsSolver().solve(_model())
    assert result.status is MILPStatus.OPTIMAL
    assert result.assignment == {"x": 3}
    assert result.objective_value == 13


@pytest.mark.parametrize("primal,status", [(None, MILPStatus.UNKNOWN), ([2], MILPStatus.FEASIBLE)])
def test_time_limits_never_establish_optimality(monkeypatch, primal, status):
    monkeypatch.setattr(
        scipy,
        "milp",
        lambda *args, **kwargs: SimpleNamespace(
            status=1, x=primal, fun=-4 if primal is not None else None, message="time limit"
        ),
    )
    assert HighsSolver().solve(_model()).status is status


def test_infeasible_returned_assignment_is_rejected(monkeypatch):
    monkeypatch.setattr(
        scipy,
        "milp",
        lambda *args, **kwargs: SimpleNamespace(status=0, x=[4], fun=-8, message="optimal"),
    )
    with pytest.raises(RuntimeError, match="infeasible assignment"):
        HighsSolver().solve(_model())


@pytest.mark.parametrize("clauses,satisfiable", [(((1,),), True), (((1,), (-1,)), False)])
def test_boolean_constraints_return_checked_sat_results(clauses, satisfiable):
    from claasp.drivers.solvers import SatStatus
    from claasp.representations.constraints.sat import CNFFormula

    formula = CNFFormula(("x",), clauses, ("clause",) * len(clauses))
    result = HighsSolver().solve(formula)
    assert result.is_satisfiable == satisfiable
    if satisfiable:
        assert result.assignment is not None and formula.is_satisfied(result.assignment)
    else:
        assert result.status is SatStatus.UNSATISFIABLE and result.assignment is None


def test_boolean_timeout_without_witness_is_not_unsat(monkeypatch):
    from claasp.representations.constraints.sat import CNFFormula

    monkeypatch.setattr(
        scipy,
        "milp",
        lambda *args, **kwargs: SimpleNamespace(status=1, x=None, fun=None, message="time limit"),
    )
    formula = CNFFormula(("x",), ((1,),), ("clause",))
    with pytest.raises(RuntimeError, match="unknown.*not proved"):
        HighsSolver().solve(formula)


def test_boolean_time_limit_with_checked_incumbent_proves_sat(monkeypatch):
    from claasp.representations.constraints.sat import CNFFormula

    monkeypatch.setattr(
        scipy,
        "milp",
        lambda *args, **kwargs: SimpleNamespace(status=1, x=[1.0], fun=0.0, message="time limit"),
    )
    formula = CNFFormula(("x",), ((1,),), ("clause",))
    result = HighsSolver().solve(formula)
    assert result.is_satisfiable and result.assignment == {"x": 1}


def test_fractional_boolean_incumbent_is_rejected_before_rounding(monkeypatch):
    from claasp.representations.constraints.sat import CNFFormula

    # A feasible LP relaxation is insufficient for a Boolean witness.
    count = 20
    monkeypatch.setattr(
        scipy,
        "milp",
        lambda *args, **kwargs: SimpleNamespace(
            status=1, x=[0.05] * count, fun=0.0, message="time limit"
        ),
    )
    formula = CNFFormula(
        tuple(f"x{i}" for i in range(count)), (tuple(range(1, count + 1)),), ("clause",)
    )
    # Integrality is checked by the MILP validator before Boolean validation.
    with pytest.raises(RuntimeError, match="infeasible assignment"):
        HighsSolver().solve(formula)


def test_empty_boolean_conjunction_has_the_empty_satisfying_assignment():
    from claasp.representations.constraints.sat import CNFFormula

    formula = CNFFormula((), (), ())
    result = HighsSolver().solve(formula)
    assert result.is_satisfiable and result.assignment == {}
    assert formula.is_satisfied(result.assignment)
