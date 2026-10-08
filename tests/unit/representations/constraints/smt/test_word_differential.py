"""Fast graph wiring and independent differential witness checks."""

from dataclasses import replace

import pytest

from claasp import Primitive, ValueType, Word
from claasp.components import BitwiseAnd, Xor
from claasp.drivers.solvers import SatResult, SatStatus
from claasp.representations.constraints.smt import WordDifferentialSMTModel
from claasp.representations.constraints.smt.word_differential import (
    WordDifferentialEnumeration,
)


def _primitive(component):
    primitive = Primitive(
        "boolean_word", {"left": ValueType(Word(2), (1,)), "key": ValueType(Word(2), (1,))}
    )
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        component((primitive.graph.input("left"), primitive.graph.input("key")))
    )
    primitive._builder.set_output(output)
    return primitive


def test_xor_difference_propagation_is_forward_not_mask_fanout():
    model = WordDifferentialSMTModel(_primitive(Xor), maximum_weight=0)
    formula = model.smt_formula()
    assignment = dict.fromkeys(formula.variables, 0)
    for name in model._ports["left"]:
        assignment[name] = 1
    for name in model._output:
        assignment[name] = 1
    trail = model.decode_characteristic(assignment)
    assert dict(trail.input_differences) == {"left": 3, "key": 0}
    assert trail.output_difference == 3 and model.check_characteristic(trail)
    cluster = WordDifferentialEnumeration((trail,), True, 0)
    assert cluster.cluster_probability() == 1
    assert WordDifferentialEnumeration((), True, 0).cluster_probability() == 0
    with pytest.raises(ValueError, match="common"):
        replace(cluster, trails=(trail, replace(trail, output_difference=0))).cluster_probability()
    assert not model.check_characteristic(replace(trail, output_difference=0))
    assignment[model._output[0]] = 0
    with pytest.raises(ValueError, match="invalid"):
        model.decode_characteristic(assignment)


def test_and_declared_weights_are_independently_recounted():
    model = WordDifferentialSMTModel(_primitive(BitwiseAnd), fixed_weight=2)
    formula = model.smt_formula()
    assignment = dict.fromkeys(formula.variables, 1)
    for name in formula.variables:
        if name.startswith("weight_complement"):
            assignment[name] = 0
    trail = model.decode_characteristic(assignment)
    assert trail.total_weight == 2 and model.check_characteristic(trail)
    values = dict(trail.semantic_assignment)
    values[next(name for name in values if name.startswith("weight_"))] = 0
    assert not model.check_characteristic(replace(trail, semantic_assignment=tuple(values.items())))


def test_incomplete_differential_enumeration_is_not_a_count_proof():
    model = WordDifferentialSMTModel(_primitive(Xor), maximum_weight=0)

    class Solver:
        def solve(self, formula):
            return SatResult(SatStatus.SATISFIABLE, dict.fromkeys(formula.variables, 0), 0, "", "")

    result = model.enumerate_trails(Solver(), limit=1)
    assert not result.complete and len(result.trails) == 1
    with pytest.raises(RuntimeError, match="incomplete"):
        result.require_complete()
    with pytest.raises(RuntimeError, match="incomplete"):
        result.cluster_probability()


@pytest.mark.parametrize(
    "options",
    [
        dict(fixed_weight=-1),
        dict(maximum_weight=True),
        dict(fixed_weight=1, maximum_weight=2),
        dict(nonzero_input="missing"),
        dict(output_difference=4),
        dict(fixed_input_differences={"key": 4}),
    ],
)
def test_invalid_differential_model_requests(options):
    with pytest.raises(ValueError):
        WordDifferentialSMTModel(_primitive(Xor), **options)
