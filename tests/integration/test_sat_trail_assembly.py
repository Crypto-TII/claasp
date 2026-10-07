"""Whole-graph SAT trail fixtures through the canonical command-line solvers."""

import pytest

from claasp.drivers.solvers import CryptoMiniSatSolver, KissatSolver, MinisatSolver
from claasp.primitives import ToySpeck
from claasp.representations.constraints.sat import (
    WordDifferentialSATModel,
    WordLinearSATModel,
)

pytestmark = pytest.mark.external


@pytest.mark.parametrize("solver_type", [MinisatSolver, KissatSolver, CryptoMiniSatSolver])
def test_toy_speck_differential_fixed_weight_count(solver_type):
    model = WordDifferentialSATModel(
        ToySpeck(2),
        fixed_weight=1,
        nonzero_input="plaintext",
        fixed_input_differences={"key": 0},
    )
    result = model.enumerate_trails(solver_type(timeout_seconds=10), limit=10).require_complete()
    assert len(result.trails) == 6
    assert all(
        trail.total_weight == 1 and model.check_characteristic(trail) for trail in result.trails
    )
    assert dict(result.reproducibility)["backend"] == "sat"


def test_toy_speck_linear_single_key_count_with_cryptominisat():
    model = WordLinearSATModel(
        ToySpeck(3),
        maximum_weight=1,
        nonzero_input="plaintext",
        fixed_inputs={"key": 0},
    )
    result = model.enumerate_trails(
        CryptoMiniSatSolver(timeout_seconds=10), limit=20
    ).require_complete()
    assert len(result.trails) == 13
    assert sum(trail.total_weight == 1 for trail in result.trails) == 12
    assert all(dict(trail.input_masks)["key"] == 0 for trail in result.trails)
    assert all(model.check_characteristic(trail) for trail in result.trails)
