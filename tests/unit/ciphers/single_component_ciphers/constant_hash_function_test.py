from claasp.ciphers.single_component_ciphers.constant_hash_function import ConstantHashFunction


def test_constant_hash_function():
    constant = ConstantHashFunction()
    assert constant.type == 'hash_function'
    assert constant.family_name == 'constant_hash_function'
    assert constant.number_of_rounds == 1
    assert constant.id == 'constant_hash_function_o3_r1'
    assert constant.component_from(0, 0).id == 'constant_0_0'

    constant = ConstantHashFunction(output_bit_size=4, value=0b1010)
    assert constant.id == 'constant_hash_function_o4_r1'
    assert constant.evaluate([]) == 0b1010

    intermediate_output = constant.evaluate([], intermediate_output=True)[1]
    assert intermediate_output['cipher_output'] == [0b1010]