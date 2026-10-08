import pytest

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import Present
from claasp.representations.constraints.milp import (
    PresentActiveSBoxesMILPModel,
    PresentDifferentialMILPModel,
    check_present_milp_trail,
)

pytestmark = pytest.mark.external


def test_glpk_proves_and_extracts_present_two_round_optimum():
    primitive = Present(number_of_rounds=2)
    lowering = PresentDifferentialMILPModel(primitive)
    model = lowering.milp_model()
    result = GLPKSolver(timeout_seconds=30).solve(model)
    trail = lowering.decode_trail(result.assignment)

    assert result.status is MILPStatus.OPTIMAL
    assert result.objective_value == 4
    assert trail.total_weight == 4
    assert check_present_milp_trail(primitive, trail)


def test_glpk_proves_present_two_round_active_sbox_optimum():
    primitive = Present(number_of_rounds=2)
    lowering = PresentActiveSBoxesMILPModel(primitive)
    result = GLPKSolver(timeout_seconds=30).solve(lowering.milp_model())
    trail = lowering.decode_trail(result.assignment)

    assert result.status is MILPStatus.OPTIMAL
    assert result.objective_value == 2
    assert sum(step.transition.input_pattern.value != 0 for step in trail.steps) == 2
    assert check_present_milp_trail(primitive, trail)
