"""Portable generic Word-trail MILP solving through GLPK."""

import pytest

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import ToySpeck
from claasp.representations.constraints.milp import (
    WordDifferentialMILPModel,
    WordLinearMILPModel,
)

pytestmark = pytest.mark.external


@pytest.mark.parametrize(
    "model",
    (
        WordDifferentialMILPModel(
            ToySpeck(2),
            fixed_weight=1,
            fixed_input_differences={"key": 0},
            nonzero_input="plaintext",
        ),
        WordLinearMILPModel(
            ToySpeck(3),
            maximum_weight=1,
            fixed_inputs={"key": 0},
            nonzero_input="plaintext",
        ),
    ),
)
def test_glpk_solves_and_independently_checks_word_trails(model):
    solved = GLPKSolver(timeout_seconds=30).solve(model.milp_model())
    assert solved.status is MILPStatus.OPTIMAL
    trail = model.decode_characteristic(solved.assignment)
    assert 0 <= trail.total_weight <= 1
    assert model.check_characteristic(trail)
