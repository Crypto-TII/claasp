"""Complete CP trail assembly."""

from claasp.primitives import Present, Speck, ToySpeck
from claasp.representations.constraints.cp import (
    PresentActiveSBoxesCPModel,
    PresentFixedActiveSBoxesCPModel,
    SpeckARXWindowDifferentialCPModel,
    SpeckSemiDeterministicTruncatedCPModel,
    WordDeterministicDifferentialLinearCPModel,
    WordDeterministicTruncatedCPModel,
    WordDifferentialCPModel,
    WordLinearCPModel,
    WordSemiDeterministicDifferentialLinearCPModel,
)
from claasp.semantics import XOR_DIFFERENTIAL
from claasp.semantics.cryptanalysis import PropagationProblem


def test_speck_arx_window_cp_adds_one_pruning_constraint_per_round():
    model = SpeckARXWindowDifferentialCPModel(
        PropagationProblem(
            Speck(number_of_rounds=3), XOR_DIFFERENTIAL, maximum_weight=45
        ),
        window_sizes=(3, 3, 3),
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (15, 56)
    assert query.constraint_models[0].model == model.model_provenance


def test_present_active_sboxes_cp_reuses_exact_tables():
    query = PresentActiveSBoxesCPModel(Present(number_of_rounds=2)).cp_model()
    assert (len(query.declarations), len(query.constraints)) == (288, 65)
    assert query.solve.startswith("solve minimize")
    assert query.constraint_models[0].model == PresentActiveSBoxesCPModel.model_provenance


def test_present_fixed_activity_cp_restores_weight_objective():
    model = PresentFixedActiveSBoxesCPModel(
        Present(number_of_rounds=2), active_sboxes=2
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (288, 66)
    assert query.constraints[-1].endswith("= 2;")
    assert query.solve.startswith("solve minimize round_1_sbox_0_weight")
    assert query.constraint_models[0].model == model.model_provenance


def test_semi_deterministic_truncated_cp_assembles_complete_speck_graph():
    model = SpeckSemiDeterministicTruncatedCPModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (672, 3483)
    assert query.constraint_models[0].model == model.model_provenance


def test_semi_deterministic_differential_linear_cp_assembles_complete_composition():
    model = WordSemiDeterministicDifferentialLinearCPModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        middle_maximum_scaled_weight=None,
        linear_maximum_weight=16,
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (2303, 6599)
    assert query.constraint_models[0].model == model.model_provenance


def test_differential_linear_cp_assembles_complete_composition():
    model = WordDeterministicDifferentialLinearCPModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        linear_maximum_weight=16,
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (2543, 7151)
    assert query.constraint_models[0].model == model.model_provenance


def test_deterministic_truncated_cp_assembles_complete_word_graph():
    model = WordDeterministicTruncatedCPModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
        output_pattern="???0????",
    )
    query = model.cp_model()
    assert len(query.declarations) == 200
    assert len(query.constraints) == 829
    assert query.constraint_models[0].model == model.model_provenance


def test_differential_cp_assembles_complete_word_graph():
    model = WordDifferentialCPModel(
        ToySpeck(2),
        fixed_weight=1,
        fixed_input_differences={"key": 0},
        nonzero_input="plaintext",
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (187, 501)
    assert query.constraint_models[0].model == model.model_provenance


def test_linear_cp_assembles_complete_word_graph():
    model = WordLinearCPModel(
        ToySpeck(3), maximum_weight=1, fixed_inputs={"key": 0}, nonzero_input="plaintext"
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (296, 706)
    assert query.constraint_models[0].model == model.model_provenance
