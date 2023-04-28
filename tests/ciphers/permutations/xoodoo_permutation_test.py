from claasp.ciphers.permutations.xoodoo_permutation import XoodooPermutation


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

    xoodoo_permutation = XoodooPermutation(number_of_rounds=1)
    plaintext = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x000000120000000000000000000000000000000900000000000000000000000000000000000000000000000000000000
    assert xoodoo_permutation.evaluate([plaintext]) == ciphertext

    xoodoo_permutation = XoodooPermutation(number_of_rounds=3)
    plaintext = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x8ad1373a05425c035bfc32401109245109e890a183e9f075929b003c79f22441b0bc1a7e93626968389900d2a8027958
    assert xoodoo_permutation.evaluate([plaintext]) == ciphertext
