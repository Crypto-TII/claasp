import pytest

from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation


def test_keccak_permutation():
    keccak = KeccakPermutation()
    assert keccak.family_name == 'keccak'
    assert keccak.type == 'permutation'
    assert keccak.number_of_rounds == 24
    assert keccak.word_bit_size == 64
    assert keccak.id == 'keccak_p1600_o1600_r24'
    assert keccak.component_from(0, 0).id == 'xor_0_0'
    assert keccak.component_from(23, 0).id == 'xor_23_0'

    keccak = KeccakPermutation(number_of_rounds=4, word_size=64)
    assert keccak.number_of_rounds == 4
    assert keccak.id == 'keccak_p1600_o1600_r4'
    assert keccak.component_from(3, 0).id == 'xor_3_0'


def test_keccak_permutation_official_reference_vector():
    """Check Keccak-f[1600](0) against the XKCP reference implementation [XKCPREF]_.

    The vector was generated with XKCP commit eb5244d6b95fb1c434b211bac293093e18aa8fd1. CLAASP emits lanes in the
    standard ``x + 5*y`` order as 64-bit values; XKCP's byte interface serializes each of those lanes little-endian.
    """
    keccak = KeccakPermutation(number_of_rounds=24)
    plaintext = 0
    ciphertext = int('0xf1258f7940e1dde784d5ccf933c0478ad598261ea65aa9eebd1547306f80494d8b284e056253d057ff97a42d7f8e6'
                     'fd490fee5a0a44647c48c5bda0cd6192e76ad30a6f71b19059c30935ab7d08ffc64eb5aa93f2317d635a9a6e6260d71'
                     '210381a57c16dbcf555f43b831cd0347c82601f22f1a11a5569f05e5635a21d9ae6164befef28cc970f2613670957bc'
                     '46611b87c5a554fd00ecb8c3ee88a1ccf32c8940c7922ae3a26141841f924a2c509e416f53526e70465c275f644e97f'
                     '30a13beaf1ff7b5ceca249', 16)
    assert keccak.evaluate([plaintext]) == ciphertext
    assert keccak.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext

    # Keccak-p[b, nr] applies the last nr rounds of Keccak-f[b]. On zero input, one round leaves only the last
    # round constant in lane (0, 0).
    keccak_last_round = KeccakPermutation(number_of_rounds=1)
    ciphertext = 0x8000000080008008 << (24 * 64)
    assert keccak_last_round.evaluate([0]) == ciphertext


def test_keccak_permutation_invalid_parameters():
    with pytest.raises(ValueError):
        KeccakPermutation(word_size=48)

    with pytest.raises(ValueError):
        KeccakPermutation(number_of_rounds=25, word_size=64)
