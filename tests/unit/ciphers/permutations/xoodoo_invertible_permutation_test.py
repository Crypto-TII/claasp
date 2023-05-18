from claasp.ciphers.permutations.xoodoo_invertible_permutation import XoodooInvertiblePermutation


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

    xoodoo_invertible_permutation = XoodooInvertiblePermutation(number_of_rounds=1)
    plaintext = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x000000120000000000000000000000000000000900000000000000000000000000000000000000000000000000000000
    assert xoodoo_invertible_permutation.evaluate([plaintext]) == ciphertext

    xoodoo_invertible_permutation = XoodooInvertiblePermutation(number_of_rounds=3)
    plaintext = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x8ad1373a05425c035bfc32401109245109e890a183e9f075929b003c79f22441b0bc1a7e93626968389900d2a8027958
    assert xoodoo_invertible_permutation.evaluate([plaintext]) == ciphertext
