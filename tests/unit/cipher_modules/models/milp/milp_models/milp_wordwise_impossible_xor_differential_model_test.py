from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import \
    MilpWordwiseImpossibleXorDifferentialModel


def test_build_wordwise_impossible_xor_differential_trail_model():
    aes = AESBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
    milp.init_model_in_sage_milp_class()
    milp._forward_cipher = aes.get_partial_cipher(0, 1, keep_key_schedule=True)
    backward_cipher = milp._cipher.cipher_partial_inverse(1, 1, keep_key_schedule=False)
    milp._backward_cipher = backward_cipher.add_suffix_to_components("_backward", [backward_cipher.get_all_components_ids()[-1]])
    milp.build_wordwise_impossible_xor_differential_trail_model()

    constraints = milp.model_constraints

    assert len(constraints) == 48392
    assert str(constraints[0]) == '1 <= 1 + x_0 - x_1 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 + x_8 + x_9'
    assert str(constraints[1]) == '1 <= 1 + x_1 - x_9'
    assert str(constraints[-2]) == 'x_3238 == x_2065'
    assert str(constraints[-1]) == 'x_3239 == x_2066'

def test_find_one_wordwise_impossible_xor_differential_trail_model():
    aes = AESBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(16),
                                    bit_values=[1, 0, 0, 3] + [0]*12)
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(128),
                              bit_values=[0] * 128)
    ciphertext = set_fixed_variables(component_id='cipher_output_1_32', constraint_type='equal', bit_positions=range(16),
                                    bit_values=[1] + [0]*15)
    trail = milp.find_one_wordwise_impossible_xor_differential_trail(1, fixed_bits=[key],
                                                                     fixed_words=[plaintext, ciphertext])
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values']['plaintext']['value'] == '1003000000000000'
    assert trail['components_values']['key']['value'] == '0000000000000000'
    assert trail['components_values']['cipher_output_1_32']['value'] == '1000000000000000'
    assert trail['components_values']['intermediate_output_0_37']['value'] == '2222333300000000'
    assert trail['components_values']['intermediate_output_0_37_backward']['value'] == '2000000000000000'



def test_find_one_wordwise_impossible_xor_differential_trail_with_fully_automatic_model():
    aes = AESBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(16),
                                    bit_values=[1, 0, 0, 3] + [0]*12)
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(128),
                              bit_values=[0] * 128)
    key_backward = set_fixed_variables(component_id='key_backward', constraint_type='equal', bit_positions=range(128),
                              bit_values=[0] * 128)
    ciphertext_backward = set_fixed_variables(component_id='cipher_output_1_32_backward', constraint_type='equal', bit_positions=range(16),
                                    bit_values=[1] + [0]*15)
    trail = milp.find_one_wordwise_impossible_xor_differential_trail_with_fully_automatic_model(fixed_bits=[key, key_backward],
                                                                     fixed_words=[plaintext, ciphertext_backward])
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values']['plaintext']['value'] == '1003000000000000'
    assert trail['components_values']['key']['value'] == '0000000000000000'
    assert trail['components_values']['cipher_output_1_32_backward']['value'] == '1000000000000000'
    assert trail['components_values']['intermediate_output_0_37']['value'] == '2222333300000000'
    assert trail['components_values']['intermediate_output_0_37_backward']['value'] == '2000000000000000'
