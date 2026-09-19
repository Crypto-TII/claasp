import pytest

from claasp_next.drivers.solvers import GLPKSolver, MILPStatus
from claasp_next.primitives import Present
from claasp_next.representations.constraints.milp import (
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
