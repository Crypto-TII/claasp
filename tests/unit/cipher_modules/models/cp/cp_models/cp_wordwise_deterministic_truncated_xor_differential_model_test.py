from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.cp.cp_models.cp_wordwise_deterministic_truncated_xor_differential_model import \
    CpWordwiseDeterministicTruncatedXorDifferentialModel


'''
def test_find_one_wordwise_deterministic_truncated_xor_differential_trail():
    aes = AESBlockCipher(number_of_rounds=2)
    cp = CpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
    plaintext = set_fixed_variables(component_id='plaintext_value', constraint_type='not_equal',
                                    bit_positions=range(16), bit_values=[0] * 16)
    key = set_fixed_variables(component_id='key_value', constraint_type='equal', bit_positions=range(16), bit_values=[0] * 16)
    trail = cp.find_one_wordwise_deterministic_truncated_xor_differential_trail(1, [plaintext, key], 'Chuffed')

    assert str(trail[0]['cipher']) == 'speck_p32_k64_o32_r1'

    assert trail[0]['components_values']['key']['value'] == '000000000000000000000000000000000000000000000000000000' \
                                                            '0000000000'
    assert trail[0]['model_type'] == 'deterministic_truncated_xor_differential_one_solution'
    assert trail[0]['solver_name'] == 'Chuffed'
'''
