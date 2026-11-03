"""Real float-solver execution; candidates are replayed through the typed graph."""

import os

import pytest

from claasp.drivers.solvers import MiniZincSolver
from claasp.primitives import ModularAdd

pytestmark = pytest.mark.external


@pytest.mark.parametrize("difference", [1, "0?"])
def test_real_solver_keeps_named_output_and_matches_the_independent_recurrence(difference):
    # Gecode is supplied by the MiniZinc CI job. A local installation can select
    # its solver configuration without modifying any user-owned preferences.
    solver = MiniZincSolver(
        os.environ.get("CLAASP_CONTINUOUS_CP_SOLVER", "gecode"), timeout_seconds=30
    )
    result = (
        ModularAdd(2)
        .analysis.continuous_differential()
        .find_best_correlation(difference, output_mask=1, solver=solver)
    )
    assert result.claim_kind == "heuristic"
    assert result.model_complete
    assert result.output_mask == 1
    assert result.correlation == pytest.approx(1.0)
    assert len(result.output_values) == 2
    assert set(result.inputs) == {"input_0", "input_1"}
