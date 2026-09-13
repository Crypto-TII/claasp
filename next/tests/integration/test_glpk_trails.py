import pytest

from claasp_next.ciphers import PresentBlockCipher
from claasp_next.milp import PresentDifferentialMILPModel, check_present_milp_trail
from claasp_next.milp.solvers import GLPKSolver, MILPStatus


pytestmark = pytest.mark.external


def test_glpk_proves_and_extracts_present_two_round_optimum():
    cipher = PresentBlockCipher(number_of_rounds=2)
    lowering = PresentDifferentialMILPModel(cipher)
    model = lowering.milp_model()
    result = GLPKSolver(timeout_seconds=30).solve(model)
    trail = lowering.decode_trail(result.assignment)

    assert result.status is MILPStatus.OPTIMAL
    assert result.objective_value == 4
    assert trail.total_weight == 4
    assert check_present_milp_trail(cipher, trail)
