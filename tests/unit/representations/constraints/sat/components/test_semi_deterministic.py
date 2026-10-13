"""Parity checks for recovered semi-deterministic SAT windows."""

import pytest

from claasp.representations.constraints.sat import (
    ModularAddSemiDeterministicTruncatedSATModel,
    ProbabilisticTruncatedModularAddSATModel,
)
from claasp.representations.constraints.sat.components._semi_deterministic_templates import (
    SOURCE_SHA256,
    WINDOW_TEMPLATES,
)


def test_generated_templates_match_the_reviewed_legacy_utility():
    assert SOURCE_SHA256 == "817ce0f3404f3b03a1d88769bdb88f7403f6991d1049af438395d78533784ce5"
    assert {window: len(clauses) for window, clauses in WINDOW_TEMPLATES.items()} == {
        0: 100,
        1: 134,
        2: 49,
        3: 54,
    }


def test_semi_deterministic_formula_preserves_window_selection_and_clause_order():
    formula = ModularAddSemiDeterministicTruncatedSATModel(6).cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        54,
        401,
        2665,
    )
    assert formula.provenance[7:61] == ("semi_deterministic_window_3",) * 54
    assert formula.provenance[61:115] == ("semi_deterministic_window_3",) * 54
    assert formula.provenance[115:164] == ("semi_deterministic_window_2",) * 49
    assert formula.clauses[:7] == (
        (-11,),
        (-23,),
        (-35,),
        (12, 24, -36),
        (12, -24, 36),
        (-12, 24, 36),
        (-12, -24, -36),
    )


def test_semi_deterministic_relation_is_compact_on_a_shared_weight_fixture():
    options = {
        "left_pattern": "0001",
        "right_pattern": "0000",
        "output_pattern": "0001",
    }
    exact = ProbabilisticTruncatedModularAddSATModel(4, **options).cnf_formula()
    recovered = ModularAddSemiDeterministicTruncatedSATModel(4, **options).cnf_formula()
    assert (recovered.variable_count, recovered.clause_count) == (36, 317)
    assert recovered.variable_count < exact.variable_count
    assert recovered.clause_count < exact.clause_count


def test_semi_deterministic_model_validates_width_and_patterns():
    with pytest.raises(ValueError, match="at least two"):
        ModularAddSemiDeterministicTruncatedSATModel(1)
    with pytest.raises(ValueError, match="contain 4 bits"):
        ModularAddSemiDeterministicTruncatedSATModel(4, left_pattern="0")
