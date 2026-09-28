from claasp.ciphers.permutations.xoodoo_sbox_permutation import XoodooSboxPermutation


def _little_endian_words_to_int(value):
    data = bytes.fromhex(value)
    words = [int.from_bytes(data[i:i + 4], 'little') for i in range(0, len(data), 4)]

    return int(''.join(format(word, '032b') for word in words), 2)


def test_xoodoo_sbox_permutation():
    xoodoo_permutation_sbox = XoodooSboxPermutation()
    assert xoodoo_permutation_sbox.family_name == 'xoodoo_sbox'
    assert xoodoo_permutation_sbox.type == 'permutation'
    assert xoodoo_permutation_sbox.number_of_rounds == 12
    assert xoodoo_permutation_sbox.id == 'xoodoo_sbox_p384_o384_r12'
    assert xoodoo_permutation_sbox.component_from(0, 0).id == 'xor_0_0'

    xoodoo_permutation_sbox = XoodooSboxPermutation(number_of_rounds=3)
    assert xoodoo_permutation_sbox.number_of_rounds == 3
    assert xoodoo_permutation_sbox.id == 'xoodoo_sbox_p384_o384_r3'
    assert xoodoo_permutation_sbox.component_from(2, 0).id == 'xor_2_0'

    xoodoo_permutation_sbox = XoodooSboxPermutation(number_of_rounds=12)
    plaintext = 0
    # XKCP commit eb5244d6b95fb1c434b211bac293093e18aa8fd1, with little-endian lanes converted to CLAASP words.
    ciphertext = _little_endian_words_to_int(
        '8dd8d589bffc63a9192d231b14a0a5ff0681b136fec1c7afbe7ce5aebd4075a7'
        '70e8862ec9b7f5fef2ad4f8b62404f5e'
    )
    assert xoodoo_permutation_sbox.evaluate([plaintext]) == ciphertext
    assert xoodoo_permutation_sbox.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
