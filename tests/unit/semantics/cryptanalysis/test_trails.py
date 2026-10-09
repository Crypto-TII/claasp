from math import inf

import pytest

from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    Transition,
    XorDifference,
    XorMask,
)


def test_present_sbox_exact_differential_transition_and_impossibility():
    semantics = SBoxTransitionSemantics(PRESENT_SBOX)
    possible = semantics.xor_differential(0x1, 0x3)
    impossible = semantics.xor_differential(0x1, 0x1)

    assert (possible.numerator, possible.denominator, possible.weight) == (4, 16, 2.0)
    assert semantics.check(possible)
    assert not impossible.is_possible
    assert impossible.weight == inf


def test_present_sbox_exact_signed_linear_transition():
    transition = SBoxTransitionSemantics(PRESENT_SBOX).xor_linear(0x1, 0x5)

    assert (transition.numerator, transition.denominator) == (8, 16)
    assert transition.sign == -1
    assert transition.weight == 1.0


def test_rectangular_lookup_has_distinct_input_and_output_widths():
    semantics = SBoxTransitionSemantics((0, 1, 3, 2, 1, 0, 2, 3))

    assert (semantics.width, semantics.output_width) == (3, 2)
    assert len(semantics.difference_distribution_table()) == 8
    assert len(semantics.difference_distribution_table()[0]) == 4
    assert semantics.xor_differential(1, 1).output_pattern.width == 2
    assert semantics.xor_linear(1, 1).output_pattern.width == 2


def test_lookup_preserves_a_declared_output_width_with_leading_zero_bits():
    semantics = SBoxTransitionSemantics((0, 0, 1, 1), output_width=3)

    assert semantics.output_width == 3
    assert len(semantics.difference_distribution_table()[0]) == 8
    assert semantics.xor_differential(1, 0).output_pattern.width == 3


def test_dense_lookup_tables_reject_unbounded_output_materialization():
    semantics = SBoxTransitionSemantics((0, 1 << 20))

    with pytest.raises(NotImplementedError, match="dense DDT"):
        semantics.difference_distribution_table()
    with pytest.raises(NotImplementedError, match="dense Walsh"):
        semantics.walsh_correlation_table()

    square = SBoxTransitionSemantics(tuple(range(1 << 11)))
    with pytest.raises(NotImplementedError, match="table cells"):
        square.difference_distribution_table()


def test_trail_weight_is_the_sum_of_independently_checkable_steps():
    semantics = SBoxTransitionSemantics(PRESENT_SBOX)
    transition = semantics.xor_differential(0x1, 0x3)
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(0x1, 4),
        XorDifference(0x3, 4),
        (TrailStep("present_sbox", transition),),
    )

    assert trail.total_weight == 2.0
    assert semantics.check(trail.steps[0].transition)


def test_transition_kinds_and_pattern_widths_are_explicit():
    with pytest.raises(TypeError, match="XorDifference"):
        Transition(
            TrailKind.XOR_DIFFERENTIAL,
            XorMask(1, 4),
            XorMask(3, 4),
            4,
            16,
        )
    with pytest.raises(ValueError, match="fit"):
        XorDifference(16, 4)
