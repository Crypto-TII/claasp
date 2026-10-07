"""Whole-graph SAT trail assembly and independent witness checks."""

from dataclasses import replace

import pytest

from claasp import Primitive, ValueType, Word
from claasp.components import BitwiseAnd, ModularAdd, Xor
from claasp.primitives import ToySpeck
from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.sat import (
    NWindowSATStrategy,
    WordDeterministicTruncatedSATModel,
    WordDifferentialSATModel,
    WordLinearSATModel,
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
