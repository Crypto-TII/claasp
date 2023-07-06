import os
import pytest

from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_fixing_number_of_active_sboxes_model \
    import (CpXorDifferentialFixingNumberOfActiveSboxesModel)
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list


def test_find_all_xor_differential_trails_with_fixed_weight():
    aes = AESBlockCipher(number_of_rounds=2)
    cp = CpXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [set_fixed_variables('key', 'equal', range(128), integer_to_bit_list(0, 128, 'little')),
                       set_fixed_variables('plaintext', 'not_equal', range(128), integer_to_bit_list(0, 128, 'little'))]
    trails = cp.find_all_xor_differential_trails_with_fixed_weight(30, fixed_variables, 'Chuffed', 'Chuffed')

    assert len(trails) == 255


def test_find_lowest_weight_xor_differential_trail():
    aes = AESBlockCipher(number_of_rounds=2)
    cp = CpXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [set_fixed_variables('key', 'equal', range(128), integer_to_bit_list(0, 128, 'little')),
                       set_fixed_variables('plaintext', 'not_equal', range(128), integer_to_bit_list(0, 128, 'little'))]
    solution = cp.find_lowest_weight_xor_differential_trail(fixed_variables, 'Chuffed', 'Chuffed')

    assert solution['cipher_id'] == 'aes_block_cipher_k128_p128_o128_r2'
    assert solution['model_type'] == 'xor_differential'
    assert solution['solver_name'] == 'Chuffed'
    assert solution['total_weight'] == '30.0'
    assert solution['components_values']['key'] == {'value': '00000000000000000000000000000000', 'weight': 0}
    assert eval('0x' + solution['components_values']['plaintext']['value']) > 0
    assert solution['components_values']['plaintext']['weight'] == 0
    assert eval('0x' + solution['components_values']['cipher_output_1_32']['value']) >= 0
    assert solution['components_values']['cipher_output_1_32']['weight'] == 0


def test_find_one_xor_differential_trail():
    aes = AESBlockCipher(number_of_rounds=2)
    cp = CpXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [set_fixed_variables('key', 'equal', range(128), integer_to_bit_list(0, 128, 'little')),
                       set_fixed_variables('plaintext', 'not_equal', range(128), integer_to_bit_list(0, 128, 'little'))]
    solution = cp.find_one_xor_differential_trail(fixed_variables, 'Chuffed', 'Chuffed')

    assert solution['cipher_id'] == 'aes_block_cipher_k128_p128_o128_r2'
    assert solution['model_type'] == 'xor_differential'
    assert solution['solver_name'] == 'Chuffed'
    assert eval(solution['total_weight']) >= 0.0
    assert solution['components_values']['key'] == {'value': '00000000000000000000000000000000', 'weight': 0}
    assert solution['components_values']['plaintext']['weight'] == 0


def test_find_one_xor_differential_trail_with_fixed_weight():
    aes = AESBlockCipher(number_of_rounds=2)
    cp = CpXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [set_fixed_variables('key', 'equal', range(128), integer_to_bit_list(0, 128, 'little')),
                       set_fixed_variables('plaintext', 'not_equal', range(128), integer_to_bit_list(0, 128, 'little'))]
    solution = cp.find_one_xor_differential_trail_with_fixed_weight(224, fixed_variables, 'Chuffed', 'Chuffed')

    assert solution['cipher_id'] == 'aes_block_cipher_k128_p128_o128_r2'
    assert solution['model_type'] == 'xor_differential'
    assert solution['solver_name'] == 'Chuffed'
    assert eval(solution['total_weight']) == 224.0
    assert solution['components_values']['key'] == {'value': '00000000000000000000000000000000', 'weight': 0}
    assert eval('0x' + solution['components_values']['plaintext']['value']) > 0
    assert solution['components_values']['plaintext']['weight'] == 0
    assert solution['components_values']['cipher_output_1_32']['weight'] == 0


def test_solve_full_two_steps_xor_differential_model():
    aes = AESBlockCipher(number_of_rounds=2)
    cp = CpXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [
        set_fixed_variables('key', 'not_equal', list(range(128)), integer_to_bit_list(0, 128, 'little'))]
    constraints = cp.solve_full_two_steps_xor_differential_model('xor_differential_one_solution', -1, fixed_variables, 'Chuffed', 'Chuffed')

    assert constraints['cipher_id'] == 'aes_block_cipher_k128_p128_o128_r2'
    assert eval('0x' + constraints['components_values']['intermediate_output_0_35']['value']) >= 0
    assert constraints['components_values']['intermediate_output_0_35']['weight'] == 0
    assert eval('0x' + constraints['components_values']['xor_0_36']['value']) >= 0
    assert constraints['components_values']['xor_0_36']['weight'] == 0
    assert eval('0x' +  constraints['components_values']['intermediate_output_0_37']['value']) >= 0
    assert constraints['components_values']['intermediate_output_0_37']['weight'] == 0
    assert eval(constraints['total_weight']) >= 0
