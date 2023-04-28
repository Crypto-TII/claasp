from claasp.ciphers.block_ciphers.constant_block_cipher import ConstantBlockCipher


def test_constant_block_cipher():
    constant = ConstantBlockCipher()
    assert constant.type == 'block_cipher'
    assert constant.family_name == 'constant'
    assert constant.number_of_rounds == 3
    assert constant.id == 'constant_o3_r3'
    assert constant.component_from(0, 0).id == 'constant_0_0'

    constant = ConstantBlockCipher(block_bit_size=3, number_of_rounds=3)
    assert constant.type == 'block_cipher'
    assert constant.number_of_rounds == 3
    assert constant.id == "constant_o3_r3"
    assert constant.component_from(2, 0).id == 'constant_2_0'
    assert constant.as_python_dictionary()['cipher_id'] == 'constant_o3_r3'
    assert constant.as_python_dictionary()['cipher_type'] == 'block_cipher'
    assert constant.as_python_dictionary()['cipher_output_bit_size'] == 3
    assert len(constant.as_python_dictionary()['cipher_rounds']) == 3

    intermediate_output = constant.evaluate([], intermediate_output=True)[1]
    assert intermediate_output["cipher_output"] == [2]
    assert intermediate_output["round_output"] == [0, 1]

    constant = ConstantBlockCipher(block_bit_size=3, number_of_rounds=3)
    ciphertext = 2
    assert constant.evaluate([]) == ciphertext
