from claasp.ciphers.permutations.tinyjambu_32bits_word_permutation import TinyJambuWordBasedPermutation


def test_tinyjambu_32bits_word_permutation():
    tinyjambu = TinyJambuWordBasedPermutation()
    assert tinyjambu.family_name == 'tinyjambu_word_based'
    assert tinyjambu.type == 'permutation'
    assert tinyjambu.number_of_rounds == 20
    assert tinyjambu.id == 'tinyjambu_word_based_p128_k128_o128_r20'
    assert tinyjambu.component_from(0, 0).id == 'and_0_0'

    tinyjambu = TinyJambuWordBasedPermutation()
    key = 0x00000000000000000000000000000000
    plaintext = 0x00000000000000000000000000000000
    ciphertext = 0xc07a21053c7ca049e687585d161fbad7
    assert tinyjambu.evaluate([plaintext, key]) == ciphertext

    key1 = 0x12345678123456781234567812345678
    plaintext1 = 0x00000000000000000000000000000000
    ciphertext1 = 0xc5ab9fd3b28ba7586609b18a319338a8
    key2 = 0x12345678123456781234567812345678
    plaintext2 = 0x12345678123456781234567812345678
    ciphertext2 = 0x3d96877c3722415e7bfbf2e78cbb6390
    input_list = [[plaintext1, key1], [plaintext2, key2]]
    output_list = [ciphertext1, ciphertext2]
    assert tinyjambu.test_vector_check(input_list, output_list) is True
