from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.smt.smt_models.smt_cipher_model import SmtCipherModel


def test_find_missing_bits():
    speck = SpeckBlockCipher(number_of_rounds=22)
    cipher_output_id = speck.get_all_components_ids()[-1]
    smt = SmtCipherModel(speck)
    ciphertext = set_fixed_variables(component_id=cipher_output_id,
                                     constraint_type='equal',
                                     bit_positions=range(32),
                                     bit_values=integer_to_bit_list(0x1234abcd, 32, 'big'))

    missing_bits = smt.find_missing_bits(fixed_values=[ciphertext])

    assert missing_bits['cipher_id'] == 'speck_p32_k64_o32_r22'
    assert missing_bits['model_type'] == 'cipher'
    assert missing_bits['solver_name'] == 'z3'
    assert missing_bits['components_values'][cipher_output_id] == {'value': '1234abcd'}
    assert missing_bits['status'] == 'SATISFIABLE'
