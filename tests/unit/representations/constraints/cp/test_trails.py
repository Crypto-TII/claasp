"""Complete CP trail assembly."""

from types import SimpleNamespace

from claasp import Primitive, ValueType, Word
from claasp.components import ModularAdd
from claasp.primitives import Present, Speck, ToySpeck
from claasp.representations.constraints.cp import (
    ModularAddBoomerangCPModel,
    ModularAddBoomerangTrailCPModel,
    ModularAddBoomerangTrailResult,
    PresentActiveSBoxesCPModel,
    PresentDifferentialCPModel,
    PresentFixedActiveSBoxesCPModel,
    PresentHybridImpossibleCPModel,
    PresentProbabilisticKeyScheduleCPModel,
    SBoxBoomerangCPModel,
    SBoxBoomerangTrailCPModel,
    SBoxBoomerangTrailResult,
    SpeckARXWindowDifferentialCPModel,
    SpeckBoomerangCPModel,
    SpeckContinuousHeuristicCPModel,
    SpeckContinuousMaskOptimizationCPModel,
    SpeckSemiDeterministicTruncatedCPModel,
    WordDeterministicDifferentialLinearCPModel,
    WordDeterministicTruncatedCPModel,
    WordDifferentialCPModel,
    WordImpossibleCPModel,
    WordLinearCPModel,
    WordSemiDeterministicDifferentialLinearCPModel,
)
from claasp.semantics import XOR_DIFFERENTIAL
from claasp.semantics.cryptanalysis import PropagationProblem


def _single_add(name):
    primitive = Primitive(
        name,
        {
            "left": ValueType(Word(4), (1,)),
            "right": ValueType(Word(4), (1,)),
        },
    )
    primitive.add_round()
    primitive.set_output(
        primitive.add_component(ModularAdd((primitive.input("left"), primitive.input("right"))))
    )
    return primitive


def _boomerang_model():
    options = {
        "maximum_weight": 3,
        "nonzero_input": "left",
        "fixed_input_differences": {"right": 0},
    }
    return ModularAddBoomerangTrailCPModel(
        WordDifferentialCPModel(_single_add("upper"), **options),
        WordDifferentialCPModel(_single_add("lower"), **options),
        ModularAddBoomerangCPModel(4),
        lower_input="left",
    )


def test_boomerang_results_separate_search_score_from_squared_trail_probability():
    upper = SimpleNamespace(total_weight=2)
    switch = SimpleNamespace(weight=1)
    lower = SimpleNamespace(total_weight=3)

    modular_add = ModularAddBoomerangTrailResult(upper, switch, lower)
    sbox = SBoxBoomerangTrailResult(upper, switch, lower, 0)

    assert (modular_add.search_weight, modular_add.total_weight) == (5, 11)
    assert (sbox.search_weight, sbox.total_weight) == (5, 11)


def test_modadd_boomerang_cp_namespaces_and_links_complete_trails():
    query = _boomerang_model().cp_model()
    assert query.solve.startswith("solve minimize")
    assert "constraint switch_delta_left[0] = bool2int(upper_" in query.source()
    assert "constraint switch_nabla_right[0] = bool2int(lower_" in query.source()
    assert query.constraint_models[0].model == ModularAddBoomerangTrailCPModel.model_provenance
    assert query.constraint_models[1].model == ModularAddBoomerangCPModel.model_provenance


def test_sbox_boomerang_cp_namespaces_and_links_complete_present_trails():
    upper = PresentDifferentialCPModel(
        PropagationProblem(Present(number_of_rounds=2), XOR_DIFFERENTIAL, maximum_weight=8)
    )
    lower = PresentDifferentialCPModel(
        PropagationProblem(Present(number_of_rounds=2), XOR_DIFFERENTIAL, maximum_weight=8)
    )
    sbox = next(
        component
        for component in upper.primitive.components
        if component.component_id == "sbox_1_0"
    )
    model = SBoxBoomerangTrailCPModel(upper, lower, SBoxBoomerangCPModel(sbox), nibble=3)
    query = model.cp_model()
    assert query.solve == "solve maximize switch_quartet_count;"
    assert "constraint switch_input_difference = " in query.source()
    assert "constraint switch_output_difference = " in query.source()
    assert query.constraint_models[0].model == model.model_provenance
    assert query.constraint_models[1].model == SBoxBoomerangCPModel.model_provenance


def test_speck_boomerang_cp_automatically_partitions_and_links_all_switch_words():
    model = SpeckBoomerangCPModel(
        Speck(number_of_rounds=3),
        switch_round=1,
        upper_maximum_weight=20,
        lower_maximum_weight=20,
    )
    query = model.cp_model()
    source = query.source()
    assert model.upper_graph.output.value_type.unit_count == 2
    assert tuple(model.lower_graph.input_ports) == ("switch_output", "switch_right", "key")
    assert "constraint switch_delta_right[0]" in source
    assert "constraint switch_nabla_output[0]" in source
    assert query.constraint_models[-1].model == model.model_provenance


def test_generic_word_impossible_cp_preserves_complete_split_formula():
    model = WordImpossibleCPModel(
        Speck(number_of_rounds=3),
        middle_round=1,
        active_input="plaintext",
        zero_difference_inputs=("key",),
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (1568, 5674)
    assert query.constraint_models[0].model == model.model_provenance


def test_speck_arx_window_cp_adds_one_pruning_constraint_per_round():
    model = SpeckARXWindowDifferentialCPModel(
        PropagationProblem(Speck(number_of_rounds=3), XOR_DIFFERENTIAL, maximum_weight=45),
        window_sizes=(3, 3, 3),
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (15, 56)
    assert query.constraint_models[0].model == model.model_provenance


def test_speck_continuous_cp_is_explicitly_heuristic_and_fixed_input():
    left = (-1.0, -1.0, -1.0, 1.0) + (-1.0,) * 12
    right = (-1.0, 1.0, -1.0, 1.0) + (-1.0,) * 12
    model = SpeckContinuousHeuristicCPModel(left, right, rounds=2)
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (10, 160)
    assert query.solve == "solve satisfy;"
    assert model.model_provenance.reference_status.value == "TBD"


def test_speck_continuous_mask_selection_is_exact_for_fixed_output():
    left = (-1.0, -1.0, -1.0, 1.0) + (-1.0,) * 12
    right = (-1.0, 1.0, -1.0, 1.0) + (-1.0,) * 12
    model = SpeckContinuousMaskOptimizationCPModel(left, right, rounds=2)
    query = model.cp_model()
    assert sum(constraint.endswith("= 1;") for constraint in query.constraints[-32:]) == 1
    assert model.absolute_correlation == max(abs(value) for value in model._expected.values)


def test_present_hybrid_impossible_cp_assembles_both_graph_directions():
    model = PresentHybridImpossibleCPModel(Present(number_of_rounds=2), middle_round=1)
    query = model.cp_model()
    assert len(model._forward_models) == len(model._backward_models) == 16
    assert len(model.nonlinear_groups) == 32
    assert query.constraint_models[0].model == model.model_provenance


def test_present_probabilistic_key_schedule_uses_exact_ddt_weights():
    model = PresentProbabilisticKeyScheduleCPModel(
        Present(number_of_rounds=2), input_difference=1 << 18
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (6, 234)
    assert query.solve == "solve minimize key_sbox_1_weight + key_sbox_2_weight;"
    assert query.constraint_models[0].model == model.model_provenance


def test_present_active_sboxes_cp_reuses_exact_tables():
    query = PresentActiveSBoxesCPModel(Present(number_of_rounds=2)).cp_model()
    assert (len(query.declarations), len(query.constraints)) == (288, 65)
    assert query.solve.startswith("solve minimize")
    assert query.constraint_models[0].model == PresentActiveSBoxesCPModel.model_provenance


def test_present_fixed_activity_cp_restores_weight_objective():
    model = PresentFixedActiveSBoxesCPModel(Present(number_of_rounds=2), active_sboxes=2)
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
