from claasp.primitives import Present, Speck, ToySpeck
from claasp.representations.constraints.milp import (
    PresentActiveSBoxesMILPModel,
    PresentDifferentialMILPModel,
    PresentFixedActiveSBoxesMILPModel,
    SpeckSemiDeterministicTruncatedMILPModel,
    WordDeterministicDifferentialLinearMILPModel,
    WordDeterministicTruncatedMILPModel,
    WordDifferentialMILPModel,
    WordLinearMILPModel,
    WordSemiDeterministicDifferentialLinearMILPModel,
)


def test_present_milp_lowering_uses_complete_exact_transition_selectors():
    lowering = PresentDifferentialMILPModel(Present(number_of_rounds=2))
    model = lowering.milp_model()

    selectors = [variable for variable in model.variables if "_choice_" in variable.name]
    assert len(selectors) == 32 * 97
    assert len(model.constraints) == 32 * 9 + 1
    # Each S-box has one zero-to-zero selector with zero objective coefficient.
    assert len(model.objective.terms) == len(selectors) - 32


def test_present_active_sbox_model_reuses_exact_feasible_region():
    primitive = Present(number_of_rounds=2)
    weighted = PresentDifferentialMILPModel(primitive).milp_model()
    active = PresentActiveSBoxesMILPModel(primitive).milp_model()
    assert active.variables == weighted.variables
    assert active.constraints == weighted.constraints
    assert len(active.objective.terms) == 32 * 96
    assert set(coefficient for _, coefficient in active.objective.terms) == {1.0}
    assert active.constraint_models[0].model == PresentActiveSBoxesMILPModel.model_provenance


def test_present_fixed_activity_model_keeps_weight_objective():
    model = PresentFixedActiveSBoxesMILPModel(
        Present(number_of_rounds=2), active_sboxes=2
    )
    formulation = model.milp_model()
    assert (len(formulation.variables), len(formulation.constraints)) == (3296, 290)
    assert formulation.constraints[-1].name == "fixed_active_sboxes"
    assert formulation.constraints[-1].rhs == 2
    assert len(formulation.objective.terms) == 32 * 96
    assert formulation.constraint_models[0].model == model.model_provenance


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


def test_portable_deterministic_truncated_milp_preserves_formula_size():
    model = WordDeterministicTruncatedMILPModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
        output_pattern="???0????",
    )
    formulation = model.milp_model()
    assert (len(formulation.variables), len(formulation.constraints)) == (200, 829)
    assert formulation.constraint_models[0].model == model.model_provenance


def test_semi_deterministic_truncated_milp_preserves_formula_size_and_objective():
    model = SpeckSemiDeterministicTruncatedMILPModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
    )
    formulation = model.milp_model()
    assert (len(formulation.variables), len(formulation.constraints)) == (672, 3483)
    assert len(formulation.objective.terms) == 160
    assert formulation.constraint_models[0].model == model.model_provenance


def test_differential_linear_milp_preserves_formula_size_and_objective():
    model = WordDeterministicDifferentialLinearMILPModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        linear_maximum_weight=16,
    )
    formulation = model.milp_model()
    assert (len(formulation.variables), len(formulation.constraints)) == (2543, 7151)
    assert len(formulation.objective.terms) == 63
    assert set(coefficient for _, coefficient in formulation.objective.terms) == {1.0, 2.0}
    assert formulation.constraint_models[0].model == model.model_provenance


def test_semi_differential_linear_milp_preserves_formula_size_and_objective():
    model = WordSemiDeterministicDifferentialLinearMILPModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        middle_maximum_scaled_weight=None,
        linear_maximum_weight=16,
    )
    formulation = model.milp_model()
    assert (len(formulation.variables), len(formulation.constraints)) == (2303, 6599)
    assert len(formulation.objective.terms) == 63
    assert set(coefficient for _, coefficient in formulation.objective.terms) == {1.0, 2.0}
    assert formulation.constraint_models[0].model == model.model_provenance
