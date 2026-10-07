from claasp.primitives import Present, ToySpeck
from claasp.representations.constraints.milp import (
    PresentDifferentialMILPModel,
    WordDifferentialMILPModel,
    WordLinearMILPModel,
)


def test_present_milp_lowering_uses_complete_exact_transition_selectors():
    lowering = PresentDifferentialMILPModel(Present(number_of_rounds=2))
    model = lowering.milp_model()

    selectors = [variable for variable in model.variables if "_choice_" in variable.name]
    assert len(selectors) == 32 * 97
    assert len(model.constraints) == 32 * 9 + 1
    # Each S-box has one zero-to-zero selector with zero objective coefficient.
    assert len(model.objective.terms) == len(selectors) - 32


def test_portable_word_milp_trails_preserve_formula_sizes_and_objectives():
    differential = WordDifferentialMILPModel(
        ToySpeck(2),
        fixed_weight=1,
        fixed_input_differences={"key": 0},
        nonzero_input="plaintext",
    ).milp_model()
    linear = WordLinearMILPModel(
        ToySpeck(3), maximum_weight=1, fixed_inputs={"key": 0}, nonzero_input="plaintext"
    ).milp_model()
    assert (len(differential.variables), len(differential.constraints)) == (187, 501)
    assert (len(linear.variables), len(linear.constraints)) == (296, 706)
    assert len(differential.objective.terms) == 9
    assert len(linear.objective.terms) == 12
