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
