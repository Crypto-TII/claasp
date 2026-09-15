"""Legacy reduced Speck linear evidence, independently recounted after Z3."""

import shutil

import pytest

from claasp_next.analysis.arx import check_speck_linear_trail
from claasp_next.drivers.solvers import SatStatus, Z3Solver
from claasp_next.primitives import Speck
from claasp_next.representations.constraints.smt import SpeckLinearSMTModel


pytestmark = pytest.mark.external


def test_z3_preserves_three_round_speck_linear_optimum_and_fixed_weight():
    """Preserve SmtXorLinearModel's optimum 1 and feasible weight 7.

    Provenance: tests/unit/cipher_modules/models/smt/smt_models/
    smt_xor_linear_model_test.py, lowest-weight and fixed-weight tests.
    """
    assert shutil.which("z3") is not None, "the external job must install Z3"
    primitive = Speck(number_of_rounds=3)
    solver = Z3Solver(timeout_seconds=10)
    below = SpeckLinearSMTModel(primitive, maximum_weight=0)
    assert solver.solve(below.smt_formula()).status is SatStatus.UNSATISFIABLE
    for model, weight in ((SpeckLinearSMTModel(primitive, maximum_weight=1), 1),
                          (SpeckLinearSMTModel(primitive, fixed_weight=7), 7)):
        result = solver.solve(model.smt_formula())
        assert result.status is SatStatus.SATISFIABLE
        trail = model.decode_trail(result.assignment)
        assert check_speck_linear_trail(primitive, trail)
        assert trail.total_weight == weight
        changed = dict(result.assignment)
        changed["state_0_0"] ^= 1
        with pytest.raises(ValueError, match="assignment disagrees"):
            model.decode_trail(changed)


@pytest.mark.parametrize("weight", [0, 17])
def test_z3_exact_weight_handles_zero_and_out_of_range(weight):
    model = SpeckLinearSMTModel(Speck(number_of_rounds=1), fixed_weight=weight)
    result = Z3Solver(timeout_seconds=10).solve(model.smt_formula())
    if weight == 0:
        assert result.status is SatStatus.SATISFIABLE
        assert model.decode_trail(result.assignment).total_weight == 0
    else:
        assert result.status is SatStatus.UNSATISFIABLE
