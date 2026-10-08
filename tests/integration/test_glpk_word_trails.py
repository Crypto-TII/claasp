"""Portable generic Word-trail MILP solving through GLPK."""

import pytest

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import Speck, ToyAES, ToySpeck
from claasp.representations.constraints.milp import (
    SpeckImpossibleMILPModel,
    SpeckSemiDeterministicTruncatedMILPModel,
    WordDeterministicDifferentialLinearMILPModel,
    WordDeterministicTruncatedMILPModel,
    WordDifferentialMILPModel,
    WordImpossibleMILPModel,
    WordLinearMILPModel,
    WordSemiDeterministicDifferentialLinearMILPModel,
    WordwiseBranchNumberActiveSBoxesMILPModel,
)

pytestmark = pytest.mark.external


def test_glpk_recovers_toyaes_wordwise_active_sbox_sequence():
    for rounds, expected in enumerate((1, 5, 9, 25), start=1):
        model = WordwiseBranchNumberActiveSBoxesMILPModel(
            ToyAES(number_of_rounds=rounds),
            active_input="plaintext",
            zero_difference_inputs=("key",),
        )
        solved = GLPKSolver(timeout_seconds=30).solve(model.milp_model())
        assert solved.status is MILPStatus.OPTIMAL
        assert model.decode_activity(solved.assignment).active_sboxes == expected


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


def test_glpk_solves_and_independently_checks_deterministic_truncated_trail():
    model = WordDeterministicTruncatedMILPModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
        output_pattern="???0????",
    )
    solved = GLPKSolver(timeout_seconds=30).solve(model.milp_model())
    assert solved.status is MILPStatus.OPTIMAL
    trail = model.decode_characteristic(solved.assignment)
    assert str(trail.output_pattern) == "???0????"
    assert model.check_characteristic(trail)


def test_glpk_solves_and_decodes_speck_impossible_split():
    model = SpeckImpossibleMILPModel(Speck(number_of_rounds=3), middle_round=1)
    solved = GLPKSolver(timeout_seconds=30).solve(model.milp_model())
    assert solved.status is MILPStatus.OPTIMAL
    trail = model.decode_trail(solved.assignment)
    assert trail.boundary.is_impossible
    assert trail.boundary.contradictory_positions


def test_glpk_solves_generic_word_impossible_split():
    model = WordImpossibleMILPModel(
        Speck(number_of_rounds=3),
        middle_round=1,
        active_input="plaintext",
        zero_difference_inputs=("key",),
    )
    solved = GLPKSolver(timeout_seconds=30).solve(model.milp_model())
    assert solved.status is MILPStatus.OPTIMAL
    assert model.decode_trail(solved.assignment).boundary.is_impossible


def test_glpk_solves_and_independently_checks_semi_deterministic_truncated_trail():
    output_pattern = "???????????????1???????????????1"
    model = SpeckSemiDeterministicTruncatedMILPModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        output_pattern,
    )
    solved = GLPKSolver(timeout_seconds=30).solve(model.milp_model())
    assert solved.status is MILPStatus.OPTIMAL
    trail = model.decode_trail(solved.assignment)
    assert str(trail.output_pattern) == output_pattern
    assert len(trail.transitions) == 2


def test_glpk_solves_and_independently_checks_differential_linear_trail():
    model = WordDeterministicDifferentialLinearMILPModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        linear_maximum_weight=16,
    )
    solved = GLPKSolver(timeout_seconds=30).solve(model.milp_model())
    assert solved.status is MILPStatus.OPTIMAL
    trail = model.decode_trail(solved.assignment)
    assert trail.linear.output_mask != 0


def test_glpk_solves_and_independently_checks_semi_differential_linear_trail():
    model = WordSemiDeterministicDifferentialLinearMILPModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        middle_maximum_scaled_weight=None,
        linear_maximum_weight=16,
    )
    solved = GLPKSolver(timeout_seconds=30).solve(model.milp_model())
    assert solved.status is MILPStatus.OPTIMAL
    trail = model.decode_trail(solved.assignment)
    assert trail.linear.output_mask != 0
    assert trail.middle_weight >= 0
