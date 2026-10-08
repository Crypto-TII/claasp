"""Whole-graph SAT trail assembly and independent witness checks."""

from dataclasses import replace

import pytest

from claasp import Primitive, ValueType, Word
from claasp.components import BitwiseAnd, ModularAdd, Xor
from claasp.primitives import Speck, ToySpeck
from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.sat import (
    NWindowSATStrategy,
    SharedDifferencePairedWordDifferentialLinearSATModel,
    SharedDifferencePairedWordDifferentialSATModel,
    SpeckImpossibleSATModel,
    SpeckProbabilisticTruncatedSATModel,
    SpeckSemiDeterministicTruncatedSATModel,
    WordDeterministicDifferentialLinearSATModel,
    WordDeterministicTruncatedSATModel,
    WordDifferentialSATModel,
    WordImpossibleSATModel,
    WordLinearSATModel,
    WordSemiDeterministicDifferentialLinearSATModel,
    find_word_impossible_sat,
)
from claasp.representations.constraints.smt import (
    WordDifferentialSMTModel,
    WordLinearSMTModel,
)
from claasp.semantics.cryptanalysis import TruncatedXorDifference


def _primitive(component):
    primitive = Primitive(
        "boolean_word", {"left": ValueType(Word(2), (1,)), "key": ValueType(Word(2), (1,))}
    )
    primitive.add_round()
    output = primitive.add_component(component((primitive.input("left"), primitive.input("key"))))
    primitive.set_output(output)
    return primitive


def test_differential_sat_assembly_matches_shared_boolean_formula():
    primitive = _primitive(BitwiseAnd)
    sat = WordDifferentialSATModel(primitive, fixed_weight=2)
    smt = WordDifferentialSMTModel(primitive, fixed_weight=2)
    formula, shared = sat.cnf_formula(), smt.smt_formula()
    assert (formula.variables, formula.clauses, formula.provenance) == (
        shared.variables,
        shared.assertions,
        shared.provenance,
    )
    assert {item.model.backend for item in formula.constraint_models} == {ConstraintBackend.SAT}
    assignment = dict.fromkeys(formula.variables, 1)
    for name in formula.variables:
        if name.startswith("weight_complement"):
            assignment[name] = 0
    trail = sat.decode_characteristic(assignment)
    assert trail.total_weight == 2 and sat.check_characteristic(trail)
    assert not sat.check_characteristic(replace(trail, output_difference=0))


def test_shared_difference_paired_sat_recovers_modadd_exclusion_and_weight_bound():
    model = SharedDifferencePairedWordDifferentialSATModel(
        ToySpeck(2),
        maximum_total_weight=2,
        fixed_input_differences={"key": 0},
        nonzero_input="plaintext",
    )
    formula = model.cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        230,
        788,
        2645,
    )
    assert formula.provenance.count("paired_modadd_output_exclusion") == 12
    assert formula.provenance.count("paired_shared_input_difference") == 48


def test_shared_difference_paired_sat_validates_total_weight_configuration():
    with pytest.raises(ValueError, match="choose"):
        SharedDifferencePairedWordDifferentialSATModel(
            ToySpeck(2), maximum_total_weight=1, fixed_total_weight=1
        )
    with pytest.raises(ValueError, match="nonnegative"):
        SharedDifferencePairedWordDifferentialSATModel(ToySpeck(2), maximum_total_weight=True)


def test_shared_difference_paired_differential_linear_sat_assembles_both_boundaries():
    model = SharedDifferencePairedWordDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=2,
        paired_differential_maximum_weight=32,
        linear_maximum_weight=16,
        fixed_total_weight=8,
    )
    formula = model.cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        13608,
        29492,
        77847,
    )
    assert formula.provenance.count("paired_differential_linear_boundary") == 64


def test_shared_difference_paired_differential_linear_sat_validates_configuration():
    with pytest.raises(ValueError, match="both be nonempty"):
        SharedDifferencePairedWordDifferentialLinearSATModel(
            Speck(number_of_rounds=3),
            prefix_rounds=3,
            paired_differential_maximum_weight=1,
            linear_maximum_weight=1,
        )
    with pytest.raises(ValueError, match="choose"):
        SharedDifferencePairedWordDifferentialLinearSATModel(
            Speck(number_of_rounds=3),
            prefix_rounds=2,
            paired_differential_maximum_weight=1,
            linear_maximum_weight=1,
            maximum_total_weight=1,
            fixed_total_weight=1,
        )


def test_linear_sat_assembly_matches_shared_boolean_formula():
    primitive = _primitive(Xor)
    sat = WordLinearSATModel(primitive, maximum_weight=0, nonzero_input="key")
    smt = WordLinearSMTModel(primitive, maximum_weight=0, nonzero_input="key")
    formula, shared = sat.cnf_formula(), smt.smt_formula()
    assert (formula.variables, formula.clauses, formula.provenance) == (
        shared.variables,
        shared.assertions,
        shared.provenance,
    )
    assert {item.model.backend for item in formula.constraint_models} == {ConstraintBackend.SAT}
    trail = sat.decode_characteristic(dict.fromkeys(formula.variables, 1))
    assert dict(trail.input_masks) == {"left": 3, "key": 3}
    assert trail.output_mask == 3 and sat.check_characteristic(trail)


@pytest.mark.parametrize("model_type", [WordDifferentialSATModel, WordLinearSATModel])
def test_sat_enumeration_rejects_nonpositive_or_boolean_limits(model_type):
    primitive = _primitive(Xor)
    options = (
        {"maximum_weight": 0} if model_type is WordDifferentialSATModel else {"maximum_weight": 0}
    )
    model = model_type(primitive, **options)
    with pytest.raises(ValueError, match="positive integer"):
        model.enumerate_trails(object(), limit=True)


def test_n_window_strategy_is_opt_in_and_supports_legacy_selectors():
    primitive = ToySpeck(2)
    exact = WordDifferentialSATModel(primitive, fixed_weight=1).cnf_formula()
    uniform = WordDifferentialSATModel(
        primitive, fixed_weight=1, n_window=NWindowSATStrategy(2)
    ).cnf_formula()
    by_round = WordDifferentialSATModel(
        primitive,
        fixed_weight=1,
        n_window=NWindowSATStrategy(by_round=(2, 2)),
    ).cnf_formula()
    component_windows = {
        component.component_id: 2
        for component in primitive.components
        if isinstance(component, ModularAdd)
    }
    by_component = WordDifferentialSATModel(
        primitive,
        fixed_weight=1,
        n_window=NWindowSATStrategy(by_component=component_windows),
    ).cnf_formula()
    assert "n_window_run_bound" not in exact.provenance
    assert uniform.clauses == by_round.clauses == by_component.clauses
    assert any(
        item.model.encoding_name == "direct carry-difference run bound"
        for item in uniform.constraint_models
    )


def test_n_window_strategy_rejects_incomplete_component_configuration():
    model = WordDifferentialSATModel(
        ToySpeck(2),
        fixed_weight=1,
        n_window=NWindowSATStrategy(by_component={"unknown": 2}),
    )
    with pytest.raises(ValueError, match="every modular-add component"):
        model.cnf_formula()


def test_deterministic_truncated_sat_assembles_and_independently_checks_toy_speck():
    model = WordDeterministicTruncatedSATModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
    )
    formula = model.cnf_formula()
    assert formula.variable_count == 200
    assert formula.clause_count == 813
    assert any(item.model == model.model_provenance for item in formula.constraint_models)
    assert any(
        item.model.encoding_name == "legacy two-bit paired-carry clauses"
        for item in formula.constraint_models
    )


def test_deterministic_truncated_sat_restriction_validation():
    primitive = ToySpeck(2)
    with pytest.raises(ValueError, match="unknown fixed input"):
        WordDeterministicTruncatedSATModel(primitive, fixed_input_patterns={"missing": "0"})
    with pytest.raises(ValueError, match="contain 8 bits"):
        WordDeterministicTruncatedSATModel(primitive, fixed_input_patterns={"plaintext": "0"})
    model = WordDeterministicTruncatedSATModel(
        primitive,
        fixed_input_patterns={
            "plaintext": TruncatedXorDifference.parse("00000001"),
            "key": "0" * 16,
        },
        output_pattern="???0????",
    )
    assert "truncated_fixed_output" in model.cnf_formula().provenance


def test_speck_impossible_sat_composes_transformed_directional_graphs():
    model = SpeckImpossibleSATModel(Speck(number_of_rounds=3), middle_round=1)
    formula = model.cnf_formula()
    assert formula.variable_count == 1568
    assert formula.clause_count == 5674
    assert "truncated_incompatibility_exists" in formula.provenance
    assert any(item.model == model.model_provenance for item in formula.constraint_models)
    assert any(
        item.model.component_model == "ModularSubtractDeterministicTruncatedSATModel"
        for item in formula.constraint_models
    )


def test_generic_word_impossible_sat_matches_reviewed_speck_composition():
    generic = WordImpossibleSATModel(
        Speck(number_of_rounds=3),
        middle_round=1,
        active_input="plaintext",
        zero_difference_inputs=("key",),
    ).cnf_formula()
    specialized = SpeckImpossibleSATModel(Speck(number_of_rounds=3), middle_round=1).cnf_formula()
    assert generic.variables == specialized.variables
    assert generic.clauses == specialized.clauses


def test_speck_impossible_sat_validates_supported_slice_and_patterns():
    primitive = Speck(number_of_rounds=3)
    with pytest.raises(ValueError, match="inside the primitive"):
        SpeckImpossibleSATModel(primitive, middle_round=0)
    with pytest.raises(TypeError, match="integer"):
        SpeckImpossibleSATModel(primitive, middle_round=True)
    with pytest.raises(ValueError, match="contain 32 bits"):
        SpeckImpossibleSATModel(primitive, middle_round=1, input_pattern="0")


def test_automatic_impossible_search_validates_explicit_split_order():
    with pytest.raises(ValueError, match="unique internal"):
        find_word_impossible_sat(
            Speck(number_of_rounds=3),
            object(),
            active_input="plaintext",
            zero_difference_inputs=("key",),
            split_order=(1, 1),
        )


def test_speck_probabilistic_sat_assembles_local_round_relations():
    model = SpeckProbabilisticTruncatedSATModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
    )
    formula = model.cnf_formula()
    assert formula.variable_count == 1182
    assert formula.clause_count == 215309
    assert len(model._round_models) == 2
    assert all(item.model.backend is ConstraintBackend.SAT for item in formula.constraint_models)


def test_speck_probabilistic_sat_validates_boundaries_and_weight_bound():
    primitive = Speck(number_of_rounds=2)
    with pytest.raises(ValueError, match="32 bits"):
        SpeckProbabilisticTruncatedSATModel(primitive, "0", "0" * 32)
    with pytest.raises(ValueError, match="nonnegative integer"):
        SpeckProbabilisticTruncatedSATModel(
            primitive, "0" * 32, "0" * 32, maximum_scaled_weight=True
        )


def test_speck_semi_deterministic_sat_reuses_graph_assembly_compactly():
    portable = SpeckProbabilisticTruncatedSATModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
        maximum_scaled_weight=100,
    ).cnf_formula()
    model = SpeckSemiDeterministicTruncatedSATModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
        maximum_scaled_weight=100,
    )
    formula = model.cnf_formula()
    assert formula.variable_count > 0
    assert formula.clause_count < portable.clause_count
    assert len(model._round_models) == 2
    assert any(item.model == model.model_provenance for item in formula.constraint_models)


def test_deterministic_differential_linear_sat_assembles_three_round_slices():
    model = WordDeterministicDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        linear_maximum_weight=16,
    )
    formula = model.cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        2543,
        7151,
        23144,
    )
    assert "differential_to_truncated_exact" in formula.provenance
    assert "truncated_to_linear_compatibility" in formula.provenance
    assert "nonzero_differential_linear_output_mask" in formula.provenance


def test_deterministic_differential_linear_sat_validates_partition_and_bounds():
    primitive = Speck(number_of_rounds=3)
    with pytest.raises(ValueError, match="positive"):
        WordDeterministicDifferentialLinearSATModel(
            primitive,
            prefix_rounds=0,
            middle_rounds=1,
            differential_maximum_weight=1,
            linear_maximum_weight=1,
        )
    with pytest.raises(ValueError, match="all be nonempty"):
        WordDeterministicDifferentialLinearSATModel(
            primitive,
            prefix_rounds=1,
            middle_rounds=2,
            differential_maximum_weight=1,
            linear_maximum_weight=1,
        )
    with pytest.raises(ValueError, match="nonnegative"):
        WordDeterministicDifferentialLinearSATModel(
            primitive,
            prefix_rounds=1,
            middle_rounds=1,
            differential_maximum_weight=-1,
            linear_maximum_weight=1,
        )


def test_semi_deterministic_differential_linear_sat_assembles_recovered_middle():
    model = WordSemiDeterministicDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        middle_maximum_scaled_weight=None,
        linear_maximum_weight=16,
    )
    formula = model.cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        2303,
        6599,
        22737,
    )
    assert "semi_deterministic_weight_code" in formula.provenance
    assert formula.provenance.count("differential_to_truncated_exact") == 96
    assert formula.provenance.count("truncated_to_linear_compatibility") == 32


def test_semi_deterministic_differential_linear_sat_validates_configuration():
    with pytest.raises(NotImplementedError, match="supports Speck"):
        WordSemiDeterministicDifferentialLinearSATModel(
            ToySpeck(3),
            prefix_rounds=1,
            middle_rounds=1,
            differential_maximum_weight=1,
            middle_maximum_scaled_weight=None,
            linear_maximum_weight=1,
        )
