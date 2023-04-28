import pytest

from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel


def test_solve():
    # testing with system solver
    tea = TeaBlockCipher(number_of_rounds=32)
    sat = SatCipherModel(tea)
    sat.build_cipher_model()
    solution = sat.solve('cipher', solver_name='cryptominisat')
    assert solution['cipher_id'] == 'tea_p64_k128_o64_r32'
    assert solution['solver_name'] == 'cryptominisat'
    assert eval('0x' + solution['components_values']['modadd_0_3']['value']) >= 0
    assert solution['components_values']['modadd_0_3']['weight'] >= 0
    assert solution['components_values']['modadd_0_3']['sign'] == 1
    assert eval('0x' + solution['components_values']['cipher_output_31_16']['value']) >= 0
    assert solution['components_values']['cipher_output_31_16']['weight'] == 0
    assert solution['components_values']['cipher_output_31_16']['sign'] == 1
    # testing with sage solver
    simon = SimonBlockCipher(number_of_rounds=32)
    sat = SatCipherModel(simon)
    sat.build_cipher_model()
    solution = sat.solve('cipher', solver_name='cryptominisat_sage')
    assert solution['cipher_id'] == 'simon_p32_k64_o32_r32'
    assert solution['solver_name'] == 'cryptominisat'
    assert eval('0x' + solution['components_values']['rot_0_3']['value']) >= 0
    assert solution['components_values']['rot_0_3']['weight'] >= 0
    assert solution['components_values']['rot_0_3']['sign'] == 1
    assert eval('0x' + solution['components_values']['cipher_output_31_13']['value']) >= 0
    assert solution['components_values']['cipher_output_31_13']['weight'] == 0
    assert solution['components_values']['cipher_output_31_13']['sign'] == 1


def test_fix_variables_value_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatModel(speck)
    fixed_variables = [{'component_id': 'plaintext',
                        'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [1, 0, 1, 1]},
                       {'component_id': 'ciphertext',
                        'constraint_type': 'not_equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [1, 1, 1, 0]}]
    assert sat.fix_variables_value_constraints(fixed_variables) == [
        'plaintext_0', '-plaintext_1', 'plaintext_2', 'plaintext_3',
        '-ciphertext_0 -ciphertext_1 -ciphertext_2 ciphertext_3']


def test_model_constraints():
    with pytest.raises(Exception):
        speck = SpeckBlockCipher(number_of_rounds=4)
        sat = SatModel(speck)
        sat.model_constraints()


def test_weight_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorDifferentialModel(speck)
    sat.build_xor_differential_trail_model()
    assert len(sat.weight_constraints(7)) == 2
