"""GLPK basic-LP status differs from its integer-solution record."""

import pytest

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.representations.constraints.milp import LinearVariable, MILPModel


@pytest.mark.parametrize(
    "primal,dual,expected",
    [
        ("f", "f", MILPStatus.OPTIMAL),
        ("f", "u", MILPStatus.FEASIBLE),
        ("n", "f", MILPStatus.INFEASIBLE),
        ("i", "u", MILPStatus.UNKNOWN),
        ("u", "u", MILPStatus.UNKNOWN),
    ],
)
def test_basic_status_needs_primal_and_dual_feasibility(primal, dual, expected):
    model = MILPModel((LinearVariable("x"),), ())
    text = f"s bas 0 1 {primal} {dual} 2\nj 1 b 2 0\n"
    status, assignment, objective = GLPKSolver._parse_solution(text, model, {1: "x"})
    assert status is expected
    if expected in {MILPStatus.OPTIMAL, MILPStatus.FEASIBLE}:
        assert assignment == {"x": 2} and objective == 2
    else:
        assert assignment is None and objective is None
