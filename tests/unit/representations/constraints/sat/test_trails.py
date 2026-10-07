"""Whole-graph SAT trail assembly and independent witness checks."""

from dataclasses import replace

import pytest

from claasp import Primitive, ValueType, Word
from claasp.components import BitwiseAnd, Xor
from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.sat import (
    WordDifferentialSATModel,
    WordLinearSATModel,
)
from claasp.representations.constraints.smt import (
    WordDifferentialSMTModel,
    WordLinearSMTModel,
)


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
