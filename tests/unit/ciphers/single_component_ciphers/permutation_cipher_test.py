import pytest

from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher


def test_permutation_cipher_is_bijection_on_small_domain():
    cipher = PermutationCipher(bit_size=4, permutation_description=[3, 2, 1, 0])
    outputs = {cipher.evaluate([x]) for x in range(16)}
    assert cipher.type == "permutation"
    assert len(outputs) == 16


def test_permutation_cipher_default_description_reverses_bits():
    cipher = PermutationCipher(bit_size=4)

    assert cipher.evaluate([0b1100]) == 0b0011


def test_permutation_cipher_applies_correct_permutation():
    # Permutation [3, 2, 1, 0]: permutation_description[i] is the destination of source bit i
    # Source bit 0 -> output bit 3, source bit 1 -> output bit 2, source bit 2 -> output bit 1, source bit 3 -> output bit 0
    # Equivalently: output[j] = input[inverse_perm[j]]; since [3,2,1,0] is self-inverse:
    # output[0] = input[3], output[1] = input[2], output[2] = input[1], output[3] = input[0]
    # Input 0b1000 (bit 3=1, bits 2,1,0=0):
    #   output[0] = input[3] = 1
    #   output[1] = input[2] = 0
    #   output[2] = input[1] = 0
    #   output[3] = input[0] = 0
    #   Result: 0b0001
    cipher = PermutationCipher(bit_size=4, permutation_description=[3, 2, 1, 0])
    assert cipher.evaluate([0b1000]) == 0b0001
    assert cipher.evaluate([0b0001]) == 0b1000
    assert cipher.evaluate([0b1010]) == 0b0101


def test_permutation_cipher_identity_permutation():
    cipher = PermutationCipher(bit_size=8, permutation_description=list(range(8)))
    for val in range(256):
        assert cipher.evaluate([val]) == val


def test_permutation_cipher_word_size():
    # word_size=4, 8-bit input: two 4-bit words, swap them
    # description=[1, 0]: output word 0 = input word 1, output word 1 = input word 0
    # input 0xAB (word0=0xA, word1=0xB) -> output 0xBA
    cipher = PermutationCipher(bit_size=8, permutation_description=[1, 0], word_size=4)
    assert cipher.evaluate([0xAB]) == 0xBA
    assert cipher.evaluate([0x12]) == 0x21
    assert cipher.evaluate([0x00]) == 0x00
    assert cipher.evaluate([0xFF]) == 0xFF


def test_permutation_cipher_word_size_is_bijection():
    cipher = PermutationCipher(bit_size=8, permutation_description=[1, 0], word_size=4)
    outputs = {cipher.evaluate([x]) for x in range(256)}
    assert len(outputs) == 256


def test_permutation_cipher_default_word_size_description_for_words():
    cipher = PermutationCipher(bit_size=8, word_size=4)

    assert cipher.evaluate([0xAB]) == 0xBA
    assert cipher.evaluate([0x12]) == 0x21


def test_permutation_cipher_rejects_invalid_default_word_size_configuration():
    with pytest.raises(ValueError, match="bit_size must be divisible by word_size"):
        PermutationCipher(bit_size=10, word_size=4)

    with pytest.raises(ValueError, match="word_size must be a positive integer"):
        PermutationCipher(bit_size=8, word_size=0)
