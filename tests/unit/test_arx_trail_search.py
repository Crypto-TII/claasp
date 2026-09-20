from claasp.analysis.arx import check_speck_linear_trail, check_speck_trail
from claasp.primitives import Speck
from claasp.semantics.cryptanalysis import (
    ModularAddLinearSemantics,
    ModularAddTransitionSemantics,
)


def test_modular_add_transition_counts_are_exact():
    semantics = ModularAddTransitionSemantics(4)

    deterministic = semantics.xor_differential(0x8, 0, 0x8)
    impossible = semantics.xor_differential(0x8, 0, 0x1)
    assert (deterministic.numerator, deterministic.denominator, deterministic.weight) == (
        256,
        256,
        0.0,
    )
    assert not impossible.is_possible
    assert semantics.check(deterministic)


def test_two_round_speck_reproduces_legacy_optimum_and_checks_wiring():
    primitive = Speck(number_of_rounds=2)

    result = primitive.analyze().find_lowest_weight_xor_differential_trail()

    assert result.trail.total_weight == 1.0
    assert result.lower_bound == 1.0
    assert result.is_optimal
    assert result.trail.input_pattern.value == 0x00400000
    assert check_speck_trail(primitive, result.trail)


def test_modular_add_linear_correlation_retains_exact_sign():
    transition = ModularAddLinearSemantics(16).xor_linear(0x0800, 0x0800, 0x0C00)

    assert (transition.numerator, transition.denominator, transition.weight) == (
        1 << 31,
        1 << 32,
        1.0,
    )
    assert transition.sign == -1


def test_four_round_speck_reproduces_legacy_linear_optimum():
    primitive = Speck(number_of_rounds=4)

    result = primitive.analyze().find_lowest_weight_xor_linear_trail()

    assert result.trail.total_weight == 3.0
    assert result.is_optimal
    assert result.trail.input_pattern.value == 0x40B010C1
    assert result.trail.output_pattern.value == 0x2C102010
    assert check_speck_linear_trail(primitive, result.trail)
