"""Exact whole-table DDT/LAT counts, signs and fixed patterns."""

from itertools import product

import pytest

from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.representations.constraints.milp import (
    SBoxTransitionMILPModel,
    SBoxUndisturbedBitsEspressoMILPModel,
    SBoxUndisturbedBitsMILPModel,
)
from claasp.semantics.cryptanalysis import SBoxTransitionSemantics, TrailKind


@pytest.mark.parametrize("kind", [TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR])
def test_every_present_supported_transition_and_objective(kind):
    relation = SBoxTransitionMILPModel(PRESENT_SBOX, kind)
    model = relation.milp_model()
    for row in relation.relation.rows:
        witness = relation.relation.witness(row)
        transition = relation.decode_transition(witness)
        assert relation.semantics.check(transition)
        assert model.objective_value(witness) == transition.weight
    assert len(relation.relation.rows) == sum(
        relation._transition(source, target).is_possible
        for source in range(16)
        for target in range(16)
    )
    if kind is TrailKind.XOR_DIFFERENTIAL:
        # Legacy convex-hull fixture for the probability-2/16 class.
        probability_two = [
            row
            for row in relation.relation.rows
            if relation._transition(
                int("".join(map(str, row[:4])), 2), int("".join(map(str, row[4:])), 2)
            ).numerator
            == 2
        ]
        assert probability_two and all(row[3] + row[4] + row[6] >= 1 for row in probability_two)


def test_fixed_sbox_pattern_rejects_another_supported_transition():
    relation = SBoxTransitionMILPModel(PRESENT_SBOX, TrailKind.XOR_LINEAR)
    relation.milp_model(input_pattern=1, output_pattern=5)
    witness = relation.relation.witness((0, 0, 0, 1, 0, 1, 0, 1))
    transition = relation.decode_transition(witness)
    assert transition.weight == 1 and transition.sign == -1
    other = relation.relation.witness((0,) * 8)
    with pytest.raises(ValueError, match="invalid"):
        relation.decode_transition(other)


def test_complete_tables_match_independent_transition_counts():
    semantics = SBoxTransitionSemantics(PRESENT_SBOX)
    ddt, walsh = semantics.difference_distribution_table(), semantics.walsh_correlation_table()
    for alpha in range(16):
        for beta in range(16):
            assert ddt[alpha][beta] == semantics.xor_differential(alpha, beta).numerator
            transition = semantics.xor_linear(alpha, beta)
            assert walsh[alpha][beta] == transition.sign * transition.numerator


def test_rectangular_sbox_relation_uses_distinct_boundary_widths():
    table = (0, 1, 3, 2, 1, 0, 2, 3)
    relation = SBoxTransitionMILPModel(table, TrailKind.XOR_DIFFERENTIAL)
    transition = next(
        relation.semantics.xor_differential(source, target)
        for source in range(8)
        for target in range(4)
        if relation.semantics.xor_differential(source, target).is_possible
    )
    model = relation.milp_model(
        input_pattern=transition.input_pattern.value,
        output_pattern=transition.output_pattern.value,
    )
    row = tuple((transition.input_pattern.value >> bit) & 1 for bit in reversed(range(3))) + tuple(
        (transition.output_pattern.value >> bit) & 1 for bit in reversed(range(2))
    )

    assert len(model.variables) == len(relation.relation.rows) + 5
    assert relation.decode_transition(relation.relation.witness(row)) == transition


@pytest.mark.parametrize("kind", [TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR])
def test_eight_bit_baseline_does_not_drop_probability_one_active_transitions(kind):
    # An affine bijection has nonzero deterministic differences/correlations.
    relation = SBoxTransitionMILPModel(tuple(value ^ 0xA5 for value in range(256)), kind)
    relation.milp_model(input_pattern=0x55, output_pattern=0x55)
    row = tuple((value >> bit) & 1 for value in (0x55, 0x55) for bit in reversed(range(8)))
    transition = relation.decode_transition(relation.relation.witness(row))
    assert transition.weight == 0
    assert len(relation.relation.rows) == 256


def test_present_undisturbed_espresso_and_one_hot_accept_exactly_the_typed_relation():
    one_hot = SBoxUndisturbedBitsMILPModel(PRESENT_SBOX)
    espresso = SBoxUndisturbedBitsEspressoMILPModel(PRESENT_SBOX, "present")
    compact = espresso.milp_model()
    expected = set(one_hot.relation.rows)
    accepted = set()
    for row in product((0, 1), repeat=16):
        assignment = dict(zip(espresso.columns, row))
        if compact.is_feasible(assignment):
            accepted.add(row)
    assert accepted == expected
    assert len(expected) == 81


@pytest.mark.parametrize(
    "model_type,arguments",
    (
        (SBoxUndisturbedBitsMILPModel, (PRESENT_SBOX,)),
        (SBoxUndisturbedBitsEspressoMILPModel, (PRESENT_SBOX, "present")),
    ),
)
def test_present_undisturbed_models_decode_fixed_bits(model_type, arguments):
    relation = model_type(*arguments)
    model = relation.milp_model(input_pattern="0001", output_pattern="???1")
    if isinstance(relation, SBoxUndisturbedBitsEspressoMILPModel):
        witness = {
            name: value
            for name, value in zip(
                relation.columns,
                next(row for row in relation.relation.rows if row[:8] == (0, 0, 0, 0, 0, 0, 0, 1)),
            )
        }
    else:
        row = next(row for row in relation.relation.rows if row[:8] == (0, 0, 0, 0, 0, 0, 0, 1))
        witness = relation.relation.witness(row)
    source, output = relation.decode_transition(witness)
    assert str(source) == "0001"
    assert str(output) == "???1"
    assert model.is_feasible(witness)
