from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = SpeckBlockCipher(number_of_rounds=5)
    smt = SmtXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext',
                                    constraint_type='not_equal',
                                    bit_positions=range(32),
                                    bit_values=integer_to_bit_list(0, 32, 'big'))
    key = set_fixed_variables(component_id='key',
                              constraint_type='equal',
                              bit_positions=range(64),
                              bit_values=integer_to_bit_list(0, 64, 'big'))
    trails = smt.find_all_xor_differential_trails_with_weight_at_most(9, 10, fixed_values=[plaintext, key])
    assert len(trails) == 28


def test_find_lowest_weight_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    smt = SmtXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext',
                                    constraint_type='not_equal',
                                    bit_positions=range(32),
                                    bit_values=integer_to_bit_list(0, 32, 'big'))
    key = set_fixed_variables(component_id='key',
                              constraint_type='equal',
                              bit_positions=range(64),
                              bit_values=integer_to_bit_list(0, 64, 'big'))
    trail = smt.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])
    assert trail['total_weight'] == 9.0


def test_find_one_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    smt = SmtXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext',
                                    constraint_type='not_equal',
                                    bit_positions=range(32),
                                    bit_values=integer_to_bit_list(0, 32, 'big'))
    solution = smt.find_one_xor_differential_trail(fixed_values=[plaintext])
    assert solution['cipher_id'] == 'speck_p32_k64_o32_r5'
    assert solution['solver_name'] == 'z3'
    assert eval('0x' + solution['components_values']['intermediate_output_0_6']['value']) >= 0
    assert solution['components_values']['intermediate_output_0_6']['weight'] == 0
    assert solution['components_values']['intermediate_output_0_6']['sign'] == 1
    assert eval('0x' + solution['components_values']['cipher_output_4_12']['value']) >= 0
    assert solution['components_values']['cipher_output_4_12']['weight'] == 0
    assert solution['components_values']['cipher_output_4_12']['sign'] == 1


def test_find_one_xor_differential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext',
                                    constraint_type='not_equal',
                                    bit_positions=range(32),
                                    bit_values=(0,) * 32)
    key = set_fixed_variables(component_id='key',
                              constraint_type='equal',
                              bit_positions=range(64),
                              bit_values=(0,) * 64)
    result = smt.find_one_xor_differential_trail_with_fixed_weight(3, fixed_values=[plaintext, key])
    assert result['total_weight'] == 3.0
