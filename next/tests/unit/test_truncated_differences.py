from claasp_next.analysis import (
    TruncatedXorDifference,
    propagate_two_word_speck_round,
    truncated_modular_add,
)
from claasp_next.ciphers import PresentBlockCipher, SpeckBlockCipher


def test_truncated_modular_add_preserves_only_universal_output_bits():
    left = TruncatedXorDifference.parse("1000")
    right = TruncatedXorDifference.parse("0000")
    assert str(truncated_modular_add(left, right)) == "1000"

    varied = truncated_modular_add(
        TruncatedXorDifference.parse("0001"),
        TruncatedXorDifference.parse("0001"),
    )
    assert str(varied).endswith("0")


def test_speck_truncated_round_reproduces_legacy_sat_fixture():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    input_difference = TruncatedXorDifference.parse(
        "00000000011111001110000000000000"
    )

    output = propagate_two_word_speck_round(cipher, input_difference)

    assert str(output) == "????100000000000????100000000011"


def test_graph_level_impossible_sbox_transition_is_exhaustively_refuted():
    cipher = PresentBlockCipher(number_of_rounds=1)

    assert not cipher.analyze().is_xor_differential_transition_possible(
        "sbox_1_0", 0x1, 0x1
    )
    assert cipher.analyze().is_xor_differential_transition_possible(
        "sbox_1_0", 0x1, 0x3
    )
