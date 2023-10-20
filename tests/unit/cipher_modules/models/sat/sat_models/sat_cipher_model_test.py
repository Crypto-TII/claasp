from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel


def test_find_missing_bits():
    speck = SpeckBlockCipher(number_of_rounds=22)
    sat = SatCipherModel(speck)
    ciphertext = set_fixed_variables(component_id='cipher_output_21_12', constraint_type='equal',
                                     bit_positions=range(32), bit_values=[1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0,
                                                                          0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1,
                                                                          0, 1, 0, 0, 1, 1, 1, 1, 1, 1])

    missing_bits = sat.find_missing_bits(fixed_values=[ciphertext])

    assert missing_bits['cipher_id'] == 'speck_p32_k64_o32_r22'
    assert missing_bits['model_type'] == 'cipher'
    assert missing_bits['solver_name'] == 'cryptominisat'
    assert missing_bits['components_values']['cipher_output_21_12'] == {'value': 'e7c92d3f', 'weight': 0, 'sign': 1}
    assert missing_bits['total_weight'] == 0
    assert missing_bits['status'] == 'SATISFIABLE'
