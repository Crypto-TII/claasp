from claasp.ciphers.permutations.keccak_invertible_permutation import KeccakInvertiblePermutation


def test_keccak_invertible_permutation():
    keccak = KeccakInvertiblePermutation(number_of_rounds=2, word_size=64)
    assert keccak.number_of_rounds == 2
    assert keccak.id == 'keccak_invertible_p1600_o1600_r2'
    assert keccak.component_from(1, 0).id == 'theta_keccak_1_0'

    # Very long test
    keccak = KeccakInvertiblePermutation(number_of_rounds=1)
    plaintext = int('0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000', 16)
    ciphertext = 0x8000000080008008 << (24 * 64)
    assert keccak.evaluate([plaintext]) == ciphertext
    assert keccak.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
