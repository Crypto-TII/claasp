from claasp_next.primitives import Present
from claasp_next.representations.constraints.milp import PresentDifferentialMILPModel


def test_present_milp_lowering_uses_complete_exact_transition_selectors():
    lowering = PresentDifferentialMILPModel(Present(number_of_rounds=2))
    model = lowering.milp_model()

    selectors = [variable for variable in model.variables if "_choice_" in variable.name]
    assert len(selectors) == 32 * 97
    assert len(model.constraints) == 32 * 9 + 1
    # Each S-box has one zero-to-zero selector with zero objective coefficient.
    assert len(model.objective.terms) == len(selectors) - 32
