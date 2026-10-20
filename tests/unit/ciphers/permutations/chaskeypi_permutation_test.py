"""Unit tests for ChaskeyPi permutation derived vectors and half-round granularity.

REFERENCES:

Mouha, N. (2015). Chaskey: An Efficient MAC Algorithm for 32-Bit Microcontrollers.
 https://mouha.be/wp-content/uploads/chaskey12.c [Mouha2015]_.
"""

import pytest

from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation


def _rotl(value, amount, word_size):
    mask = (1 << word_size) - 1
    amount %= word_size
    return ((value << amount) | (value >> (word_size - amount))) & mask


def _reference_top_half(v, word_size):
    mask = (1 << word_size) - 1
    v0, v1, v2, v3 = v
    v0 = (v0 + v1) & mask
    v1 = _rotl(v1, 5, word_size) ^ v0
    v0 = _rotl(v0, 16, word_size)
    v2 = (v2 + v3) & mask
    v3 = _rotl(v3, 8, word_size) ^ v2
    return [v0, v1, v2, v3]


def _reference_bottom_half(v, word_size):
    mask = (1 << word_size) - 1
    v0, v1, v2, v3 = v
    v0 = (v0 + v3) & mask
    v3 = _rotl(v3, 13, word_size) ^ v0
    v2 = (v2 + v1) & mask
    v1 = _rotl(v1, 7, word_size) ^ v2
    v2 = _rotl(v2, 16, word_size)
    return [v0, v1, v2, v3]


def _reference_permutation(state, number_of_half_rounds, word_size, start_bottom=False):
    """Pure Python Chaskey-Pi on ``number_of_half_rounds`` half-rounds, following [Mouha2015]_ (chaskey12.c)."""
    mask = (1 << word_size) - 1
    v = [(state >> (word_size * (3 - i))) & mask for i in range(4)]
    for half_index in range(number_of_half_rounds):
        if (half_index + int(start_bottom)) % 2 == 0:
            v = _reference_top_half(v, word_size)
        else:
            v = _reference_bottom_half(v, word_size)
    return sum(word << (word_size * (3 - i)) for i, word in enumerate(v))


def test_chaskeypi_permutation_derived_reference_vectors():
    """Test permutation I/O vectors derived from [Mouha2015]_.

    Standalone Chaskey-Pi permutation input/output vectors are not explicitly
    listed in the original source; they were reconstructed from the published
    MAC reference vectors by treating each 128-bit message block as the
    permutation input and using the corresponding intermediate state after the
    12-round Chaskey-Pi permutation as the expected output.
    """

    chaskeypi = ChaskeyPiPermutation(number_of_rounds=12, word_size=32)

    vectors = [
        (
            0xFFAA5488AAFF00545500FFA90055AAFE,
            0x85907B5488DCD7C66F8681CE3FA86995,
        ),
        (
            0x566432879EACFAC8C7F5A3900F3D6B59,
            0xB1341B56BEEF313694054E3211A48DA3,
        ),
    ]

    for permutation_input, expected_output in vectors:
        assert chaskeypi.evaluate([permutation_input], verbosity=False) == expected_output


def test_chaskeypi_full_rounds_are_two_half_rounds():
    chaskeypi = ChaskeyPiPermutation()
    assert chaskeypi.number_of_rounds == 24

    reduced = ChaskeyPiPermutation(number_of_rounds=4, word_size=16)
    assert reduced.number_of_rounds == 8
    assert reduced.id == "chaskeypi_permutation_p64_o64_r8"


def test_chaskeypi_half_round_count():
    half = ChaskeyPiPermutation(number_of_rounds=7.5)
    assert half.number_of_rounds == 15

    single_half = ChaskeyPiPermutation(number_of_rounds=0.5, word_size=16)
    assert single_half.number_of_rounds == 1
    assert len(single_half.rounds_as_list[0].components) == 8  # 2 modadd + 2 xor + 3 rot + output


@pytest.mark.parametrize("number_of_rounds", [0.5, 1, 1.5, 2, 3.5])
@pytest.mark.parametrize("start_round", [("top",), ("bottom",)])
def test_chaskeypi_half_rounds_match_reference(number_of_rounds, start_round):
    word_size = 16
    chaskeypi = ChaskeyPiPermutation(number_of_rounds=number_of_rounds, word_size=word_size, start_round=start_round)
    number_of_half_rounds = int(number_of_rounds * 2)
    assert chaskeypi.number_of_rounds == number_of_half_rounds
    for state in (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x0000000000000001, 0xFFFFFFFFFFFFFFFF):
        expected = _reference_permutation(state, number_of_half_rounds, word_size, start_round == ("bottom",))
        assert chaskeypi.evaluate([state], verbosity=False) == expected


def test_chaskeypi_top_then_bottom_equals_full_round():
    word_size = 32
    full_round = ChaskeyPiPermutation(number_of_rounds=1, word_size=word_size)
    top_half = ChaskeyPiPermutation(number_of_rounds=0.5, word_size=word_size, start_round=("top",))
    bottom_half = ChaskeyPiPermutation(number_of_rounds=0.5, word_size=word_size, start_round=("bottom",))
    state = 0x0123456789ABCDEFFEDCBA9876543210
    after_top = top_half.evaluate([state], verbosity=False)
    assert bottom_half.evaluate([after_top], verbosity=False) == full_round.evaluate([state], verbosity=False)


def test_chaskeypi_half_round_inverse_round_trip():
    chaskeypi = ChaskeyPiPermutation(number_of_rounds=1.5, word_size=16, start_round=("bottom",))
    state = 0x0123456789ABCDEF
    output = chaskeypi.evaluate([state], verbosity=False)
    assert chaskeypi.cipher_inverse().evaluate([output], verbosity=False) == state


def test_chaskeypi_invalid_word_size_non_integer_raises():
    with pytest.raises(ValueError, match="word_size must be a positive integer"):
        ChaskeyPiPermutation(word_size=1.5)


def test_chaskeypi_invalid_word_size_non_positive_raises():
    with pytest.raises(ValueError, match="word_size must be a positive integer"):
        ChaskeyPiPermutation(word_size=0)


def test_chaskeypi_invalid_rounds_not_half_multiple_raises():
    with pytest.raises(ValueError, match="number_of_rounds must be a positive multiple of 0.5"):
        ChaskeyPiPermutation(number_of_rounds=2.3)


def test_chaskeypi_invalid_rounds_non_positive_raises():
    with pytest.raises(ValueError, match="number_of_rounds must be a positive multiple of 0.5"):
        ChaskeyPiPermutation(number_of_rounds=0)


def test_chaskeypi_invalid_rounds_boolean_raises():
    with pytest.raises(ValueError, match="number_of_rounds must be a positive multiple of 0.5"):
        ChaskeyPiPermutation(number_of_rounds=True)


def test_chaskeypi_invalid_start_round_raises():
    with pytest.raises(ValueError, match='start_round must be \\("top",\\) or \\("bottom",\\)'):
        ChaskeyPiPermutation(start_round=("middle",))


def test_chaskeypi_invalid_rotations_length_raises():
    with pytest.raises(ValueError, match="rotations must contain exactly 5 values"):
        ChaskeyPiPermutation(rotations=(-5, -8, -13, -7))


def test_chaskeypi_invalid_rotations_values_raises():
    with pytest.raises(ValueError, match="rotations values must be integers"):
        ChaskeyPiPermutation(rotations=(-5, -8, -13, -7, "-16"))
