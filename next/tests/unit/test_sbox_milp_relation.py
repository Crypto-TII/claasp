"""Exact whole-table DDT/LAT counts, signs and fixed patterns."""

import pytest

from claasp_next.primitives.block_ciphers.present import PRESENT_SBOX
from claasp_next.semantics.cryptanalysis import TrailKind
from claasp_next.semantics.cryptanalysis import SBoxTransitionSemantics
from claasp_next.representations.constraints.milp import SBoxTransitionMILPModel


@pytest.mark.parametrize("kind", [TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR])
def test_every_present_supported_transition_and_objective(kind):
    relation = SBoxTransitionMILPModel(PRESENT_SBOX, kind)
    model = relation.milp_model()
    for row in relation.relation.rows:
        witness = relation.relation.witness(row)
        transition = relation.decode_transition(witness)
        assert relation.semantics.check(transition)
        assert model.objective_value(witness) == transition.weight
    assert len(relation.relation.rows) == sum(relation._transition(source, target).is_possible
                                            for source in range(16) for target in range(16))
    if kind is TrailKind.XOR_DIFFERENTIAL:
        # Legacy convex-hull fixture for the probability-2/16 class.
        probability_two = [row for row in relation.relation.rows
                           if relation._transition(int("".join(map(str, row[:4])), 2),
                               int("".join(map(str, row[4:])), 2)).numerator == 2]
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


@pytest.mark.parametrize("kind", [TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR])
def test_eight_bit_baseline_does_not_drop_probability_one_active_transitions(kind):
    # An affine bijection has nonzero deterministic differences/correlations.
    relation = SBoxTransitionMILPModel(tuple(value ^ 0xA5 for value in range(256)), kind)
    relation.milp_model(input_pattern=0x55, output_pattern=0x55)
    row = tuple((value >> bit) & 1 for value in (0x55, 0x55) for bit in reversed(range(8)))
    transition = relation.decode_transition(relation.relation.witness(row))
    assert transition.weight == 0
    assert len(relation.relation.rows) == 256
