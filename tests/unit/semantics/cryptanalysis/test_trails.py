from math import inf

import pytest

from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    Trail,
    TrailComponentTransition,
    TrailKind,
    TrailSearchMetadata,
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


def test_rectangular_des_sbox_uses_distinct_input_and_output_widths():
    from claasp.primitives.block_ciphers.des import DES

    table = DES(number_of_rounds=1).sbox[1]
    semantics = SBoxTransitionSemantics(table, output_width=4)
    differential = semantics.xor_differential(0x34, 0x2)
    linear = semantics.xor_linear(0x10, 0xF)

    expected_differential = sum(table[value] ^ table[value ^ 0x34] == 0x2 for value in range(64))
    expected_walsh = sum(
        1 if ((value & 0x10).bit_count() + (table[value] & 0xF).bit_count()) % 2 == 0 else -1
        for value in range(64)
    )
    assert len(semantics.difference_distribution_table()) == 64
    assert len(semantics.difference_distribution_table()[0]) == 16
    assert len(semantics.walsh_correlation_table()) == 64
    assert len(semantics.walsh_correlation_table()[0]) == 16
    assert (differential.input_pattern.width, differential.output_pattern.width) == (6, 4)
    assert differential.numerator == expected_differential
    assert (linear.input_pattern.width, linear.output_pattern.width) == (6, 4)
    assert (linear.numerator, linear.sign) == (
        abs(expected_walsh),
        -1 if expected_walsh < 0 else 1,
    )
    assert semantics.check(differential)
    assert semantics.check(linear)


def test_rectangular_sbox_truncated_output_has_the_declared_width():
    from claasp.semantics.cryptanalysis import TruncatedBit, TruncatedXorDifference

    semantics = SBoxTransitionSemantics(tuple(value & 7 for value in range(64)), output_width=3)
    output = semantics.truncated_xor_differential(
        TruncatedXorDifference((TruncatedBit.ONE,) + (TruncatedBit.UNKNOWN,) * 5)
    )

    assert len(output.bits) == 3


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


def test_trail_search_metadata_distinguishes_unavailable_measurements():
    metadata = TrailSearchMetadata("exact enumeration", runtime_seconds=0.25)

    assert metadata.solver is None
    assert metadata.peak_memory_bytes is None
    with pytest.raises(ValueError, match="solver_version requires"):
        TrailSearchMetadata("exact enumeration", solver_version="1.0")


def test_component_transition_checks_embedded_local_transition_patterns():
    local = SBoxTransitionSemantics(PRESENT_SBOX).xor_differential(0x1, 0x3)

    component = TrailComponentTransition(
        0,
        "sbox_0",
        "S-box",
        XorDifference(0x1, 4),
        XorDifference(0x3, 4),
        local,
    )
    assert component.weight == 2.0
    with pytest.raises(ValueError, match="must match"):
        TrailComponentTransition(
            0,
            "sbox_0",
            "S-box",
            XorDifference(0x1, 4),
            XorDifference(0x2, 4),
            local,
        )
