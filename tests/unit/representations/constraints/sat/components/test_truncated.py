"""Exhaustive tests for truncated SAT boundary relations."""

from itertools import product
from typing import cast

import pytest

from claasp.representations.constraints.sat import (
    ImpossibleBoundarySATModel,
    ProbabilisticTruncatedModularAddSATModel,
)
from claasp.semantics.cryptanalysis import (
    ProbabilisticTruncatedModularAddTransition,
    TruncatedBit,
    TruncatedXorDifference,
    check_probabilistic_truncated_modular_add,
)


def test_impossible_boundary_indicator_is_exact_for_every_boolean_encoding():
    model = ImpossibleBoundarySATModel(1, require_incompatibility=False)
    formula = model.cnf_formula()
    for forward_unknown, forward_value, backward_unknown, backward_value, indicator in product(
        (0, 1), repeat=5
    ):
        assignment = {
            "forward_0_unknown": forward_unknown,
            "forward_0_value": forward_value,
            "backward_0_unknown": backward_unknown,
            "backward_0_value": backward_value,
            "incompatibility_0": indicator,
        }
        expected = bool(
            not forward_unknown and not backward_unknown and forward_value != backward_value
        )
        assert formula.is_satisfied(assignment) is (bool(indicator) is expected)


def test_impossible_boundary_validates_patterns_and_boolean_option():
    with pytest.raises(ValueError, match="positive integer"):
        ImpossibleBoundarySATModel(0)
    with pytest.raises(TypeError, match="must be Boolean"):
        ImpossibleBoundarySATModel(1, require_incompatibility=cast(bool, 1))
    with pytest.raises(ValueError, match="contain 2 bits"):
        ImpossibleBoundarySATModel(2, forward_pattern="0")


def test_impossible_boundary_formula_retains_legacy_six_clause_order():
    formula = ImpossibleBoundarySATModel(1, require_incompatibility=False).cnf_formula()
    assert formula.clauses == (
        (-1, -5),
        (-3, -5),
        (2, 4, -5),
        (-2, -4, -5),
        (1, 2, 3, 5, -4),
        (1, 3, 4, 5, -2),
    )
    assert set(formula.provenance) == {"truncated_incompatibility_indicator"}


def _probabilistic_assignment(transition):
    assignment = {}
    for prefix, pattern in (
        ("left", transition.left),
        ("right", transition.right),
        ("output", transition.output),
        ("carry", transition.carry_difference),
    ):
        for bit, value in enumerate(pattern.bits):
            unknown, known = value.encoded == 2, value.encoded == 1
            assignment[f"{prefix}_{bit}_unknown"] = int(unknown)
            assignment[f"{prefix}_{bit}_value"] = int(known)
    run_length = [0, 0]
    if (
        transition.left.bits[1] is TruncatedBit.ZERO
        and transition.right.bits[1] is TruncatedBit.ZERO
        and transition.carry_difference.bits[1] is TruncatedBit.UNKNOWN
    ):
        run_length[0] = 1
    for bit, selected in enumerate(run_length):
        for length in range(2):
            assignment[f"run_{bit}_{length}"] = int(length == selected)
    for bit, selected in enumerate(transition.costs):
        for cost in (0, 4, 9, 19, 41, 100):
            assignment[f"cost_{bit}_{cost}"] = int(cost == selected)
    assignment["zero_run_condition_0"] = int(run_length[0] == 1)
    return assignment


def test_probabilistic_truncated_modadd_matches_typed_relation_exhaustively_at_width_two():
    model = ProbabilisticTruncatedModularAddSATModel(2)
    formula = model.cnf_formula()
    patterns = tuple(
        TruncatedXorDifference(bits)
        for bits in product((TruncatedBit.ZERO, TruncatedBit.ONE, TruncatedBit.UNKNOWN), repeat=2)
    )
    for left, right, output, carry in product(patterns, repeat=4):
        for first_cost in (0, 4, 9, 19, 41, 100):
            transition = ProbabilisticTruncatedModularAddTransition(
                left, right, output, carry, (first_cost, 0)
            )
            assert formula.is_satisfied(_probabilistic_assignment(transition)) is (
                check_probabilistic_truncated_modular_add(transition)
            )


def test_probabilistic_truncated_modadd_validates_boundaries():
    with pytest.raises(ValueError, match="positive integer"):
        ProbabilisticTruncatedModularAddSATModel(0)
    with pytest.raises(ValueError, match="contain 2 bits"):
        ProbabilisticTruncatedModularAddSATModel(2, left_pattern="0")
