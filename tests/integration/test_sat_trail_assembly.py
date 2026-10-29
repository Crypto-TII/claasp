"""Whole-graph SAT trail fixtures through the canonical command-line solvers."""

import pytest

from claasp.drivers.solvers import CryptoMiniSatSolver, KissatSolver, MinisatSolver, SatStatus
from claasp.primitives import Speck, ToySpeck
from claasp.representations.constraints.sat import (
    NWindowSATStrategy,
    SharedDifferencePairedWordDifferentialLinearSATModel,
    SharedDifferencePairedWordDifferentialSATModel,
    WordDeterministicDifferentialLinearSATModel,
    WordDifferentialNativeXorSATModel,
    WordDifferentialSATModel,
    WordLinearNativeXorSATModel,
    WordLinearSATModel,
    WordSemiDeterministicDifferentialLinearSATModel,
)

pytestmark = pytest.mark.external


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver))
def test_semi_deterministic_differential_linear_is_solver_independent(solver_type):
    model = WordSemiDeterministicDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        middle_maximum_scaled_weight=None,
        linear_maximum_weight=16,
    )
    result = solver_type(timeout_seconds=30).solve(model.cnf_formula())
    assert result.status is SatStatus.SATISFIABLE
    trail = model.decode_trail(result.assignment)
    assert trail.linear.output_mask != 0
    assert trail.legacy_objective_weight >= 0
    assert trail.middle_weight >= 0


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver))
def test_shared_difference_paired_differential_linear_is_solver_independent(solver_type):
    model = SharedDifferencePairedWordDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=2,
        paired_differential_maximum_weight=32,
        linear_maximum_weight=16,
        fixed_total_weight=8,
    )
    result = solver_type(timeout_seconds=30).solve(model.cnf_formula())
    assert result.status is SatStatus.SATISFIABLE
    trail = model.decode_trail(result.assignment)
    assert trail.total_weight == 8
    assert trail.linear.output_mask != 0


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


def test_public_automatic_impossible_search_has_concrete_toy_validation():
    primitive = ToySpeck(3)
    result = primitive.analysis.search_impossible_differentials(
        solver=KissatSolver(timeout_seconds=20)
    )
    assert result.found and not result.complete
    candidate = result.candidates[0]
    assert candidate.trail.boundary.is_impossible
    input_pattern = str(dict(candidate.trail.forward.input_patterns)["plaintext"])
    output_pattern = str(dict(candidate.trail.backward.input_patterns)["output"])

    def matches(value, pattern):
        return all(symbol == "?" or symbol == bit for symbol, bit in zip(pattern, f"{value:08b}"))

    for key in (0, 1, 0x1234):
        outputs = []
        for x in range(256):
            output = primitive.evaluate(plaintext=x, key=key)
            assert isinstance(output, int)
            outputs.append(output)
        for difference in range(256):
            if matches(difference, input_pattern):
                assert all(
                    not matches(outputs[x] ^ outputs[x ^ difference], output_pattern)
                    for x in range(256)
                )


def test_public_present_impossible_search_and_distinct_external_pairs():
    from claasp.primitives import Present

    result = Present(number_of_rounds=2).analysis.search_impossible_differentials(
        limit=2, solver=KissatSolver(timeout_seconds=20)
    )
    assert len(result.candidates) == 2
    patterns = {
        (
            str(dict(candidate.trail.forward.input_patterns)["plaintext"]),
            str(dict(candidate.trail.backward.input_patterns)["output"]),
        )
        for candidate in result.candidates
    }
    assert len(patterns) == 2
    assert all(candidate.trail.boundary.is_impossible for candidate in result.candidates)


def test_public_differential_linear_search_optimizes_all_declared_partitions():
    from fractions import Fraction

    result = (
        ToySpeck(4)
        .analysis.find_optimal_differential_linear_trail(solver=KissatSolver(timeout_seconds=20))
        .require_complete()
    )
    assert result.found
    assert set(result.attempted_partitions) == {(1, 1, 2), (1, 2, 1), (2, 1, 1)}
    # Probability one reaches the universal upper bound, certifying this fixture.
    assert result.score == Fraction(1)
    assert result.trail.total_weight == 0


def test_public_wordwise_impossible_search_keeps_its_model_interpretation():
    from claasp.primitives import ToyAES

    result = ToyAES(
        number_of_rounds=2, word_size=4, state_size=2
    ).analysis.search_impossible_differentials(
        representation="wordwise", solver=KissatSolver(timeout_seconds=20)
    )
    assert result.found
    assert result.candidates[0].representation == "wordwise"
    assert result.candidates[0].trail.middle.contradictory_positions


def test_composed_search_api_doctests():
    """Run optional-solver API examples with their real driver in CI."""
    import doctest
    import importlib

    from claasp.analysis import (
        Analysis,
        find_optimal_differential_linear_trail,
        search_impossible_differentials,
    )

    runner = doctest.DocTestRunner()
    for method in (
        Analysis.search_impossible_differentials,
        Analysis.find_optimal_differential_linear_trail,
        search_impossible_differentials,
        find_optimal_differential_linear_trail,
    ):
        module = importlib.import_module(method.__module__)
        test = doctest.DocTestParser().get_doctest(
            method.__doc__, vars(module).copy(), method.__qualname__, module.__file__, 0
        )
        for example in test.examples:
            example.options[doctest.SKIP] = False
        runner.run(test)
    assert runner.summarize().failed == 0
