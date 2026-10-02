"""Whole-graph differential legacy fixtures via optional CLI Z3."""

from math import log2

import pytest

from claasp import Primitive, ValueType, Word
from claasp.components import Identity
from claasp.drivers.solvers import SatStatus, Z3Solver
from claasp.primitives import Speck, ToySpeck
from claasp.representations.constraints.smt.word_differential import WordDifferentialSMTModel

pytestmark = pytest.mark.external


@pytest.mark.parametrize("weight,count", [(0, 1), (1, 6)])
def test_cp_toy_speck_two_round_exact_differential_counts(weight, count):
    model = WordDifferentialSMTModel(
        ToySpeck(2),
        fixed_weight=weight,
        nonzero_input="plaintext",
        fixed_input_differences={"key": 0},
    )
    result = model.enumerate_trails(Z3Solver(timeout_seconds=10), limit=10).require_complete()
    assert len(result.trails) == count
    assert all(
        trail.total_weight == weight and model.check_characteristic(trail)
        for trail in result.trails
    )


def test_cp_toy_speck_four_round_weight_one_is_unsat():
    model = WordDifferentialSMTModel(
        ToySpeck(4),
        fixed_weight=1,
        nonzero_input="plaintext",
        fixed_input_differences={"key": 0},
    )
    assert Z3Solver(timeout_seconds=10).solve(model.smt_formula()).status is SatStatus.UNSATISFIABLE


def test_cp_toy_speck_bounded_differential_enumeration_preserves_seven():
    result = (
        ToySpeck(2)
        .analyze()
        .enumerate_xor_differential_trails(
            1,
            solver=Z3Solver(timeout_seconds=10),
            limit=10,
        )
        .require_complete()
    )
    assert len(result.trails) == 7
    assert sum(trail.total_weight == 1 for trail in result.trails) == 6


def test_cp_identity_sbox_zero_weight_and_empty_positive_weight_range():
    """The identity lookup table is superseded by the typed identity relation."""
    primitive = Primitive("identity", {"plaintext": ValueType(Word(3), (1,))})
    primitive.add_round()
    primitive.set_output(primitive.add_component(Identity(primitive.input("plaintext"))))
    for weight, count in ((0, 7), (1, 0)):
        result = (
            primitive.analyze()
            .enumerate_xor_differential_trails(
                fixed_weight=weight,
                solver=Z3Solver(timeout_seconds=10),
                limit=10,
            )
            .require_complete()
        )
        assert len(result.trails) == count
        assert all(trail.total_weight == 0 for trail in result.trails)


def test_cp_related_key_speck_four_round_zero_weight_is_feasible():
    model = WordDifferentialSMTModel(Speck(number_of_rounds=4), fixed_weight=0, nonzero_input="key")
    solved = Z3Solver(timeout_seconds=10).solve(model.smt_formula())
    assert solved.status is SatStatus.SATISFIABLE
    trail = model.decode_characteristic(solved.assignment)
    assert trail.total_weight == 0 and dict(trail.input_differences)["key"] != 0
    assert model.check_characteristic(trail)


def test_cp_speck_four_round_single_key_optimum_and_minmax_fixture():
    """Zero key difference makes minmax equal the data-path weight."""
    primitive = Speck(number_of_rounds=4)
    solver = Z3Solver(timeout_seconds=10)
    below = WordDifferentialSMTModel(
        primitive, maximum_weight=4, nonzero_input="plaintext", fixed_input_differences={"key": 0}
    )
    assert solver.solve(below.smt_formula()).status is SatStatus.UNSATISFIABLE
    optimum = WordDifferentialSMTModel(
        primitive, maximum_weight=5, nonzero_input="plaintext", fixed_input_differences={"key": 0}
    )
    solved = solver.solve(optimum.smt_formula())
    assert solved.status is SatStatus.SATISFIABLE
    trail = optimum.decode_characteristic(solved.assignment)
    assert trail.total_weight == 5 and optimum.check_characteristic(trail)
    assert all(
        step.transition.weight == 0 for step in trail.steps if step.component_id.startswith("key_")
    )


@pytest.mark.emulation_sensitive
def test_sat_fixed_nine_round_speck_cluster_preserves_27_trails_and_weight():
    """Dedicated legacy cluster check; not a routine integration workload."""
    model = WordDifferentialSMTModel(
        Speck(number_of_rounds=9),
        maximum_weight=39,
        fixed_input_differences={"plaintext": 0x8054A900, "key": 0},
        output_difference=0x00400542,
    )
    result = model.enumerate_trails(Z3Solver(timeout_seconds=45), limit=30).require_complete()
    assert len(result.trails) == 27
    assert all(
        30 <= trail.total_weight <= 39 and model.check_characteristic(trail)
        for trail in result.trails
    )
    assert round(-log2(result.cluster_probability()), 2) == 29.47
