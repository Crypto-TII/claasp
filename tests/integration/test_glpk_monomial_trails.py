"""Real GLPK composition of multi-round monomial trails."""

import pytest

from claasp.analysis import PresentMonomialSemantics
from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import Present
from claasp.representations.constraints.milp import PresentMonomialTrailMILPModel

pytestmark = pytest.mark.external


def test_glpk_recovers_and_independently_checks_two_round_present_monomial_trail():
    primitive = Present(number_of_rounds=2)
    expected = PresentMonomialSemantics(primitive).predecessor_trail(1)
    representation = PresentMonomialTrailMILPModel(
        primitive, expected.input_mask, expected.output_mask
    )

    solved = GLPKSolver(timeout_seconds=30).solve(representation.milp_model())
    trail = representation.decode_trail(solved.assignment)

    assert solved.status is MILPStatus.OPTIMAL
    assert trail.input_mask == expected.input_mask
    assert trail.output_mask == 1
    assert PresentMonomialSemantics(primitive).check(trail)
