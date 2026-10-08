"""Real GLPK composition of multi-round monomial trails."""

import pytest

from claasp.analysis import PresentMonomialSemantics
from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import Present, Simon
from claasp.representations.constraints.milp import (
    CubeMonomialFeasibilityMILPModel,
    MonomialDegreeMILPModel,
    PresentMonomialTrailMILPModel,
)

pytestmark = pytest.mark.external


def test_glpk_recovers_simon_degree_bound_and_cube_feasibility():
    primitive = Simon(number_of_rounds=1)
    degree = MonomialDegreeMILPModel(primitive, output_bit=0, variable_input="plaintext")
    optimum = GLPKSolver(timeout_seconds=30).solve(degree.milp_model())
    assert optimum.status is MILPStatus.OPTIMAL
    assert degree.decode_bound(optimum.assignment).degree == 2

    feasible = CubeMonomialFeasibilityMILPModel(
        primitive,
        output_bit=0,
        variable_input="plaintext",
        cube_positions=(1, 8),
    )
    assert GLPKSolver(timeout_seconds=30).solve(feasible.milp_model()).status is MILPStatus.OPTIMAL

    excluded = CubeMonomialFeasibilityMILPModel(
        primitive,
        output_bit=0,
        variable_input="plaintext",
        cube_positions=(0, 1),
    )
    assert (
        GLPKSolver(timeout_seconds=30).solve(excluded.milp_model()).status is MILPStatus.INFEASIBLE
    )


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
