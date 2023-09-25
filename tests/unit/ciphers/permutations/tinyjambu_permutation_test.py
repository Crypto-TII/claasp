from claasp.ciphers.permutations.tinyjambu_permutation import TinyJambuPermutation


def test_tinyjambu_permutation():
    tinyjambu = TinyJambuPermutation()
    assert tinyjambu.family_name == 'tinyjambu'
    assert tinyjambu.type == 'permutation'
    assert tinyjambu.number_of_rounds == 640
    assert tinyjambu.id == 'tinyjambu_k128_p128_o128_r640'
    assert tinyjambu.component_from(0, 0).id == 'and_0_0'

    tinyjambu = TinyJambuPermutation(number_of_rounds=4, key_bit_size=128)
    assert tinyjambu.number_of_rounds == 4
    assert tinyjambu.id == 'tinyjambu_k128_p128_o128_r4'
    assert tinyjambu.component_from(3, 0).id == 'and_3_0'

    tinyjambu = TinyJambuPermutation()
    key = 0x00000000000000000000000000000000
    plaintext = 0x00000000000000000000000000000000
    ciphertext = 0xc07a21053c7ca049e687585d161fbad7
    assert tinyjambu.evaluate([key, plaintext]) == ciphertext

    key1 = 0x12345678123456781234567812345678
    plaintext1 = 0x00000000000000000000000000000000
    ciphertext1 = 0xc5ab9fd3b28ba7586609b18a319338a8
    key2 = 0x12345678123456781234567812345678
    plaintext2 = 0x12345678123456781234567812345678
    ciphertext2 = 0x3d96877c3722415e7bfbf2e78cbb6390
    input_list = [[key1, plaintext1], [key2, plaintext2]]
    output_list = [ciphertext1, ciphertext2]
    assert tinyjambu.test_vector_check(input_list, output_list) is True
