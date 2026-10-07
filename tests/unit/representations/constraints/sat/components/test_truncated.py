"""Exhaustive tests for truncated SAT boundary relations."""

from itertools import product
from typing import cast

import pytest

from claasp.representations.constraints.sat import ImpossibleBoundarySATModel


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
