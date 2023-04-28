from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.smt.smt_models.smt_cipher_model import SmtCipherModel


def test_find_missing_bits():
    speck = SpeckBlockCipher(number_of_rounds=22)
    smt = SmtCipherModel(speck)
    ciphertext = set_fixed_variables(component_id='cipher_output_21_12',
                                     constraint_type='equal',
                                     bit_positions=range(32),
                                     bit_values=(1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1,
                                                 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1))
    solution = smt.find_missing_bits(fixed_values=[ciphertext], solver_name='yices-smt2')
    assert solution['cipher_id'] == 'speck_p32_k64_o32_r22'
    assert solution['solver_name'] == 'yices-smt2'
    assert solution['components_values']['intermediate_output_21_11'] == {'value': '093e', 'weight': 0, 'sign': 1}
    assert solution['components_values']['cipher_output_21_12'] == {'value': 'e7c92d3f', 'weight': 0, 'sign': 1}
