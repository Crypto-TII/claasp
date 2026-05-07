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
    # Permutation [3, 2, 1, 0]: output bit i = input bit perm[i]
    # Output bit 0 = input bit 3, output bit 1 = input bit 2, etc.
    # Input 0b1000 (bit 0=1, rest=0 in MSB-first indexing):
    #   output bit 0 = input bit 3 = 0
    #   output bit 1 = input bit 2 = 0
    #   output bit 2 = input bit 1 = 0
    #   output bit 3 = input bit 0 = 1  → 0b0001 = 1
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
