from claasp_next.primitives import Present
from claasp_next.representations.constraints.smt import (
    PresentDifferentialSMTModel,
    PresentLinearSMTModel,
)


def test_present_weighted_smt_formula_is_deterministic_and_scalable():
    primitive = Present(number_of_rounds=2)
    first = PresentDifferentialSMTModel(primitive, maximum_weight=4).smt_formula()
    second = PresentDifferentialSMTModel(primitive, maximum_weight=4).smt_formula()

    assert first == second
    assert len(first.variables) < 700
    assert first.assertion_count < 30000
    assert "nonzero_input" in first.provenance
    assert "weight_bound" in first.provenance


def test_present_linear_smt_formula_is_deterministic_and_bounded():
    primitive = Present(number_of_rounds=3)
    formula = PresentLinearSMTModel(primitive, maximum_weight=4).smt_formula()

    assert len(formula.variables) < 1000
    assert formula.assertion_count < 40000
    assert "nonzero_linear_input" in formula.provenance
