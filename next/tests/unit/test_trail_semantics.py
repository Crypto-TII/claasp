from math import inf

import pytest

from claasp_next.primitives.block_ciphers.present import PRESENT_SBOX
from claasp_next.semantics.cryptanalysis import (
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
