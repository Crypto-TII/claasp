"""Whole-graph SAT trail fixtures through the canonical command-line solvers."""

import pytest

from claasp.drivers.solvers import CryptoMiniSatSolver, KissatSolver, MinisatSolver
from claasp.primitives import ToySpeck
from claasp.representations.constraints.sat import (
    NWindowSATStrategy,
    WordDifferentialNativeXorSATModel,
    WordDifferentialSATModel,
    WordLinearNativeXorSATModel,
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


@pytest.mark.parametrize(
    "strategy,expected",
    (
        (NWindowSATStrategy(0), 4),
        (
            NWindowSATStrategy(1, number_of_full_windows=0, full_window_operator="exactly"),
            4,
        ),
        (
            NWindowSATStrategy(1, number_of_full_windows=1, full_window_operator="exactly"),
            2,
        ),
        (
            NWindowSATStrategy(1, number_of_full_windows=1, full_window_operator="at_least"),
            2,
        ),
        (
            NWindowSATStrategy(1, number_of_full_windows=0, full_window_operator="at_most"),
            4,
        ),
    ),
)
def test_toy_speck_n_window_counts_are_independently_checked(strategy, expected):
    model = WordDifferentialSATModel(
        ToySpeck(2),
        fixed_weight=1,
        nonzero_input="plaintext",
        fixed_input_differences={"key": 0},
        n_window=strategy,
    )
    result = model.enumerate_trails(
        CryptoMiniSatSolver(timeout_seconds=10), limit=10
    ).require_complete()
    assert len(result.trails) == expected
    assert all(model.check_characteristic(trail) for trail in result.trails)


@pytest.mark.parametrize(
    "model,expected",
    (
        (
            WordDifferentialNativeXorSATModel(
                ToySpeck(2),
                fixed_weight=1,
                nonzero_input="plaintext",
                fixed_input_differences={"key": 0},
            ),
            6,
        ),
        (
            WordLinearNativeXorSATModel(
                ToySpeck(3),
                maximum_weight=1,
                nonzero_input="plaintext",
                fixed_inputs={"key": 0},
            ),
            13,
        ),
    ),
)
def test_native_xor_trail_counts_match_ordinary_cnf(model, expected):
    result = model.enumerate_trails(
        CryptoMiniSatSolver(timeout_seconds=10), limit=20
    ).require_complete()
    assert len(result.trails) == expected
    assert dict(result.reproducibility)["formulation"] == "native_xor"
    assert all(model.check_characteristic(trail) for trail in result.trails)
