from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_model import (
    CpXorDifferentialModel, and_xor_differential_probability_ddt)


def test_and_xor_differential_probability_ddt():
    assert and_xor_differential_probability_ddt(2) == [4, 0, 2, 2, 2, 2, 2, 2]


def test_find_all_xor_differential_trails_with_fixed_weight():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
    cp = CpXorDifferentialModel(speck)
    fixed_values = [set_fixed_variables('key', 'equal', list(range(16)), integer_to_bit_list(0, 16, 'big')),
                    set_fixed_variables('plaintext', 'not_equal', list(range(8)), integer_to_bit_list(0, 8, 'big'))]
    trails = cp.find_all_xor_differential_trails_with_fixed_weight(1, fixed_values, 'Chuffed')

    assert len(trails) == 6
    
def test_solving_unsatisfiability():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
    cp = CpXorDifferentialModel(speck)
    fixed_values = [set_fixed_variables('key', 'equal', list(range(16)), integer_to_bit_list(0, 16, 'big')),
                    set_fixed_variables('plaintext', 'not_equal', list(range(8)), integer_to_bit_list(0, 8, 'big'))]
    trails = cp.find_one_xor_differential_trail_with_fixed_weight(1, fixed_values, 'Chuffed')

    assert trails['status'] == 'UNSATISFIABLE'


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
    cp = CpXorDifferentialModel(speck)
    fixed_values = [set_fixed_variables('key', 'equal', list(range(16)), integer_to_bit_list(0, 16, 'big')),
                    set_fixed_variables('plaintext', 'not_equal', list(range(8)), integer_to_bit_list(0, 8, 'big'))]
    trails = cp.find_all_xor_differential_trails_with_weight_at_most(0, 1, fixed_values, 'Chuffed')

    assert len(trails) == 7


def test_find_lowest_weight_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    cp = CpXorDifferentialModel(speck)
    fixed_values = [set_fixed_variables('key', 'equal', list(range(64)), integer_to_bit_list(0, 64, 'big')),
                    set_fixed_variables('plaintext', 'not_equal', list(range(32)), integer_to_bit_list(0, 32, 'big'))]
    trail = cp.find_lowest_weight_xor_differential_trail(fixed_values, 'Chuffed')

    assert trail['cipher_id'] == 'speck_p32_k64_o32_r5'
    assert trail['total_weight'] == '9.0'
    assert eval('0x' + trail['components_values']['cipher_output_4_12']['value']) >= 0
    assert trail['components_values']['cipher_output_4_12']['weight'] == 0


def test_find_one_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=2)
    cp = CpXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    trail = cp.find_one_xor_differential_trail([plaintext], 'Chuffed')

    assert trail['cipher_id'] == 'speck_p32_k64_o32_r2'
    assert trail['model_type'] == 'xor_differential_one_solution'
    assert eval('0x' + trail['components_values']['cipher_output_1_12']['value']) >= 0
    assert trail['components_values']['cipher_output_1_12']['weight'] == 0
    assert eval(trail['total_weight']) >= 0


def test_find_one_xor_differential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=5)
    cp = CpXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    trail = cp.find_one_xor_differential_trail_with_fixed_weight(9, [plaintext], 'Chuffed')

    assert trail['cipher_id'] == 'speck_p32_k64_o32_r5'
    assert trail['model_type'] == 'xor_differential_one_solution'
    assert eval('0x' + trail['components_values']['intermediate_output_0_5']['value']) >= 0
    assert trail['components_values']['intermediate_output_0_5']['weight'] == 0
    assert eval('0x' +  trail['components_values']['intermediate_output_1_11']['value']) >= 0
    assert trail['components_values']['intermediate_output_1_11']['weight'] == 0
    assert eval('0x' + trail['components_values']['xor_3_8']['value']) >= 0
    assert trail['components_values']['xor_3_8']['weight'] == 0
    assert trail['total_weight'] == '9.0'
