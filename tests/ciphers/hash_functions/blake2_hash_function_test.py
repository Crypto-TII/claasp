from claasp.ciphers.hash_functions.blake2_hash_function import Blake2HashFunction


def test_blake2_hash_function():
    blake2 = Blake2HashFunction()
    assert blake2.number_of_rounds == 12
    assert blake2.type == 'hash_function'
    assert blake2.family_name == 'blake2'
    assert blake2.id == 'blake2_p1024_i1024_o1024_r12'
    assert blake2.component_from(0, 0).id == 'modadd_0_0'

    blake2 = Blake2HashFunction(number_of_rounds=4)
    assert blake2.number_of_rounds == 4
    assert blake2.id == 'blake2_p1024_i1024_o1024_r4'
    assert blake2.component_from(3, 0).id == 'modadd_3_0'

    blake2 = Blake2HashFunction()
    plaintext = int('0x7d4bb1945d227b807eabaa787ec7308f4e51eecd290541cb7a4d15fed46d810f0351cec13a2842e46ca2264923a346'
                    '1219dc3a20e16aaa93a55fc2c20215bbdef35bb8040e2f4c8ccd61a0b51e36043d93e6648e0a12e21d72831ea3baddc1'
                    'c756e485e01328e5e7e17f562a41e480f444c323d9de6bcc8066a0bf408ead6eaf', 16)
    state = int('0x3d6dcf3539e97309d7e5dc918a1d1d062051c3a6becc231501bc80302076a63a1d71011d2a74552169ecd9a7e39418eca0'
                'c49757c4913fb3b767065b4d4e5e1fc4786ff9bdcca52dc9b02b7d9022f62af0cfa480b8c39ae8c6df3daa2daccc36c117b0'
                '2795fffde62f42f1f9153d44f1dc275c06ff7cb0b8c4a8e8a831569920', 16)
    output_state = int('0xdb4fe8f8204e552aa565fb99371ffc4794bba11585548aad3bc6ff5fddf43ab2da85fd9c3685d8d9e68726bc445'
                       '4bb9a7ea28b09812779f61fd8c6d7311075df4951bb88b41b52331cb234b224ee4a753557a5117fc84b2d2d0e0d64'
                       '16b8be50ddf8e3e1f4b1722743c0857bf6c7445f1d47ae8e3060320fe0ba4dd22939b7a0', 16)
    assert blake2.evaluate([plaintext, state]) == output_state
    assert blake2.test_against_reference_code(2) is True

    blake2 = Blake2HashFunction(block_bit_size=512, state_bit_size=512, word_size=32, number_of_rounds=12)
    plaintext = int('0x2f9a46cd9f2dadf749d0715e6d647ad5227f415a7bf1ca82f1d6ae7799980415b04f36887a6e05ee2e08c71fba4b49'
                    'f4998227bff25d024e2081187baed2140c', 16)
    state = int('0x16cef9be345135c32a6dc9f51563824ca03fb81c36ac82f608d424807afb77bee078cce3fb554c35359bf79dd2373b1adf'
                '994b2519e001497150ea293877ba15', 16)
    output_state = int('0xf944e1336d368c499ad83a3d18ee3825e4cae1073824afba3d3a114e1585d926e60ac2d75d21fb7b012cdb56abe'
                       'a9b7c79125928d55d3f8ddbeb1530c05a276', 16)
    assert blake2.evaluate([plaintext, state]) == output_state
    assert blake2.test_against_reference_code(2) is True
