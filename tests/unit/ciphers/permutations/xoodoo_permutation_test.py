from claasp.ciphers.permutations.xoodoo_permutation import XoodooPermutation


def _little_endian_words_to_int(value):
    data = bytes.fromhex(value)
    words = [int.from_bytes(data[i:i + 4], 'little') for i in range(0, len(data), 4)]

    return int(''.join(format(word, '032b') for word in words), 2)


def test_xoodoo_permutation():
    xoodoo_permutation = XoodooPermutation()
    assert xoodoo_permutation.family_name == 'xoodoo'
    assert xoodoo_permutation.type == 'permutation'
    assert xoodoo_permutation.number_of_rounds == 3
    assert xoodoo_permutation.id == 'xoodoo_p384_o384_r3'
    assert xoodoo_permutation.component_from(0, 0).id == 'xor_0_0'

    xoodoo_permutation = XoodooPermutation(number_of_rounds=4)
    assert xoodoo_permutation.number_of_rounds == 4
    assert xoodoo_permutation.id == 'xoodoo_p384_o384_r4'
    assert xoodoo_permutation.component_from(3, 0).id == 'xor_3_0'


def test_xoodoo_permutation_official_reference_vectors():
    """Check vectors generated with the XKCP Xoodoo reference implementation.

    The vectors were generated from XKCP commit eb5244d6b95fb1c434b211bac293093e18aa8fd1 using
    ``Xoodoo_Permute_12rounds`` and ``Xoodoo_Permute_6rounds``. XKCP serializes each 32-bit lane in little-endian
    byte order, while CLAASP integers concatenate the twelve lane values from most to least significant.
    """
    plaintext = 0
    ciphertext_12 = _little_endian_words_to_int(
        '8dd8d589bffc63a9192d231b14a0a5ff0681b136fec1c7afbe7ce5aebd4075a7'
        '70e8862ec9b7f5fef2ad4f8b62404f5e'
    )
    xoodoo_12 = XoodooPermutation(number_of_rounds=12)
    assert xoodoo_12.evaluate([plaintext]) == ciphertext_12
    assert xoodoo_12.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext_12

    ciphertext_6 = _little_endian_words_to_int(
        'a3cec928604f20add6d0c32ec5c750f02512dc08042399612d400d9e9b9bd542'
        'fc14611e97b66e187fbcdb354e10f9a1'
    )
    xoodoo_6 = XoodooPermutation(number_of_rounds=6)
    assert xoodoo_6.evaluate([plaintext]) == ciphertext_6
