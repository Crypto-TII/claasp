"""The same public trail queries must work with both free MILP drivers."""

import doctest

import pytest

from claasp.drivers.solvers import GLPKSolver, HighsSolver
from claasp.primitives import Speck, ToySpeck

pytestmark = pytest.mark.external


@pytest.mark.parametrize(
    "kind,primitive,expected",
    [
        ("linear", Speck(number_of_rounds=2), 0),
        ("differential", Speck(number_of_rounds=2), 1),
        ("differential", ToySpeck(3), 1),
    ],
)
def test_public_optimizer_keeps_the_same_proved_weight_with_highs_and_glpk(
    kind, primitive, expected
):
    for solver in (HighsSolver(timeout_seconds=60), GLPKSolver(timeout_seconds=60)):
        result = getattr(primitive.analysis, f"find_lowest_weight_xor_{kind}_trail")(solver=solver)
        assert result.is_optimal and result.trail.total_weight == expected
        assert result.metadata.solver == type(solver).__name__
        assert result.component_transitions


def test_highs_proves_the_known_three_round_speck_linear_optimum():
    # The nonzero-weight fixture was also checked independently with Z3.
    result = Speck(number_of_rounds=3).analysis.find_lowest_weight_xor_linear_trail(
        solver=HighsSolver(timeout_seconds=60)
    )
    assert result.is_optimal and result.trail.total_weight == 1
    assert result.trail.input_pattern.value != 0
    assert result.component_transitions


def test_highs_public_query_doctest_runs_with_scipy():
    import claasp.drivers.solvers.highs as module

    method = HighsSolver.solve
    assert method.__doc__ is not None
    test = doctest.DocTestParser().get_doctest(
        method.__doc__, vars(module).copy(), method.__qualname__, module.__file__, 0
    )
    assert test.examples
    runner = doctest.DocTestRunner()
    runner.run(test)
    assert runner.summarize().failed == 0
