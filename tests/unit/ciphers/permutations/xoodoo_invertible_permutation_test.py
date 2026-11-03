from claasp.ciphers.permutations.xoodoo_invertible_permutation import XoodooInvertiblePermutation


def _little_endian_words_to_int(value):
    data = bytes.fromhex(value)
    words = [int.from_bytes(data[i:i + 4], 'little') for i in range(0, len(data), 4)]

    return int(''.join(format(word, '032b') for word in words), 2)


def test_xoodoo_invertible_permutation():
    xoodoo_permutation = XoodooInvertiblePermutation()
    assert xoodoo_permutation.family_name == 'xoodoo_invertible'
    assert xoodoo_permutation.type == 'permutation'
    assert xoodoo_permutation.number_of_rounds == 12
    assert xoodoo_permutation.id == 'xoodoo_invertible_p384_o384_r12'
    assert xoodoo_permutation.component_from(0, 0).id == 'theta_xoodoo_0_0'

    xoodoo_permutation = XoodooInvertiblePermutation(number_of_rounds=4)
    assert xoodoo_permutation.number_of_rounds == 4
    assert xoodoo_permutation.id == 'xoodoo_invertible_p384_o384_r4'
    assert xoodoo_permutation.component_from(3, 0).id == 'theta_xoodoo_3_0'

    xoodoo_invertible_permutation = XoodooInvertiblePermutation(number_of_rounds=12)
    plaintext = 0
    # XKCP commit eb5244d6b95fb1c434b211bac293093e18aa8fd1, with little-endian lanes converted to CLAASP words.
    ciphertext = _little_endian_words_to_int(
        '8dd8d589bffc63a9192d231b14a0a5ff0681b136fec1c7afbe7ce5aebd4075a7'
        '70e8862ec9b7f5fef2ad4f8b62404f5e'
    )
    assert xoodoo_invertible_permutation.evaluate([plaintext]) == ciphertext
    assert xoodoo_invertible_permutation.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
