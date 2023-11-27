from claasp.ciphers.permutations.xoodoo_sbox_permutation import XoodooSboxPermutation


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

    xoodoo_permutation_sbox = XoodooSboxPermutation(number_of_rounds=1)
    plaintext = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x000000120000000000000000000000000000000900000000000000000000000000000000000000000000000000000000
    assert xoodoo_permutation_sbox.evaluate([plaintext]) == ciphertext

    xoodoo_permutation_sbox = XoodooSboxPermutation(number_of_rounds=3)
    plaintext = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x8ad1373a05425c035bfc32401109245109e890a183e9f075929b003c79f22441b0bc1a7e93626968389900d2a8027958
    assert xoodoo_permutation_sbox.evaluate([plaintext]) == ciphertext
