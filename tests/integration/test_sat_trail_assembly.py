"""Whole-graph SAT trail fixtures through the canonical command-line solvers."""

import pytest

from claasp.drivers.solvers import CryptoMiniSatSolver, KissatSolver, MinisatSolver, SatStatus
from claasp.primitives import Speck, ToySpeck
from claasp.representations.constraints.sat import (
    NWindowSATStrategy,
    SharedDifferencePairedWordDifferentialSATModel,
    WordDeterministicDifferentialLinearSATModel,
    WordDifferentialNativeXorSATModel,
    WordDifferentialSATModel,
    WordLinearNativeXorSATModel,
    WordLinearSATModel,
)

pytestmark = pytest.mark.external


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_shared_difference_paired_characteristic_is_solver_independent(solver_type):
    model = SharedDifferencePairedWordDifferentialSATModel(
        ToySpeck(2),
        fixed_total_weight=5,
        fixed_input_differences={"key": 0},
        nonzero_input="plaintext",
    )
    result = solver_type(timeout_seconds=10).solve(model.cnf_formula())
    assert result.status is SatStatus.SATISFIABLE
    trail = model.decode_trail(result.assignment)
    assert trail.total_weight == 5
    assert trail.left.input_differences == trail.right.input_differences


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_deterministic_differential_linear_speck_trail_is_solver_independent(solver_type):
    model = WordDeterministicDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        linear_maximum_weight=16,
    )
    result = solver_type(timeout_seconds=30).solve(model.cnf_formula())
    assert result.status is SatStatus.SATISFIABLE
    trail = model.decode_trail(result.assignment)
    middle_input = dict(trail.middle.input_patterns)["state"]
    assert trail.differential.output_difference == int(str(middle_input), 2)
    state_mask = dict(trail.linear.input_masks)["state"]
    assert all(
        bit.value != "?" or not (state_mask >> (31 - position)) & 1
        for position, bit in enumerate(trail.middle.output_pattern.bits)
    )
    assert trail.linear.output_mask != 0


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
