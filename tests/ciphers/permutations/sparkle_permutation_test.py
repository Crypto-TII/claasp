from claasp.ciphers.permutations.sparkle_permutation import SparklePermutation


def test_sparkle_permutation():
    sparkle = SparklePermutation()
    assert sparkle.family_name == 'sparkle'
    assert sparkle.type == 'permutation'
    assert sparkle.number_of_rounds == 7
    assert sparkle.id == 'sparkle_p256_o256_r7'
    assert sparkle.component_from(0, 0).id == 'constant_0_0'

    sparkle = SparklePermutation()
    plaintext = 0x0
    ciphertext = 0x55ce325eb69976523a53f05049546f3686c32d7bee44b8db5da5b3455772af1f
    assert sparkle.evaluate([plaintext]) == ciphertext

    plaintext = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ciphertext = 0x138f18bcbcaa5b896a46796a77f9df0dcf4787f2f73274a8cf6d4766586f67f2
    assert sparkle.evaluate([plaintext]) == ciphertext

    sparkle = SparklePermutation(number_of_blocks=8, number_of_steps=12)
    plaintext = int('0x0123456789abcdef89abcdef01234567fedcba987654321076543210fedcba980123456789abcdef89abcdef012345'
                    '67fedcba987654321076543210fedcba98', 16)
    ciphertext = int('0x00627afd81ed6af7f594e39485b6e59222ba1ed9d8b60cc900ed77965ec691586bf138b79bc1cefcbb71c93113432'
                     '6842374b2f159938253a2349c67f524daf0', 16)
    assert sparkle.evaluate([plaintext]) == ciphertext
