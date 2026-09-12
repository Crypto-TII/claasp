from claasp_next.analysis import ModularAddTransitionSemantics
from claasp_next.analysis.arx import check_speck_trail
from claasp_next.ciphers import SpeckBlockCipher


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
    cipher = SpeckBlockCipher(number_of_rounds=2)

    result = cipher.analyze().find_lowest_weight_xor_differential_trail()

    assert result.trail.total_weight == 1.0
    assert result.lower_bound == 1.0
    assert result.is_optimal
    assert result.trail.input_pattern.value == 0x00400000
    assert check_speck_trail(cipher, result.trail)
