from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import \
    MilpBitwiseImpossibleXorDifferentialModel
from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation

SIMON_INCOMPATIBLE_ROUND_OUTPUT = '????????00?????0???????0????????'
def test_build_bitwise_impossible_xor_differential_trail_model():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=2)
    milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
    milp.init_model_in_sage_milp_class()
    milp._forward_cipher = simon.get_partial_cipher(0, 1, keep_key_schedule=True)
    backward_cipher = milp._cipher.cipher_partial_inverse(1, 1, keep_key_schedule=False)
    milp._backward_cipher = backward_cipher.add_suffix_to_components("_backward", [
        backward_cipher.get_all_components_ids()[-1]])
    milp.build_bitwise_impossible_xor_differential_trail_model()

    constraints = milp.model_constraints

    assert len(constraints) == 2400
    assert str(constraints[0]) == 'x_16 == x_0'
    assert str(constraints[1]) == 'x_17 == x_1'
    assert str(constraints[-2]) == 'x_926 == x_766'
    assert str(constraints[-1]) == 'x_927 == x_767'

def test_find_one_bitwise_impossible_xor_differential_trail_model():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
    milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0] * 31 + [1])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal', bit_positions=range(32), bit_values=[0] * 6 + [2, 0, 2] + [0] * 23)
    trail = milp.find_one_bitwise_impossible_xor_differential_trail(6, fixed_values=[plaintext, key, ciphertext])
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values']['intermediate_output_5_12']['value'] == '????????????????0??????1??????0?'
    assert trail['components_values']['intermediate_output_5_12_backward']['value'] == SIMON_INCOMPATIBLE_ROUND_OUTPUT
    
def test_find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
    milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0] * 31 + [1])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    key_backward = set_fixed_variables(component_id='key_backward', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    ciphertext_backward = set_fixed_variables(component_id='cipher_output_10_13_backward', constraint_type='equal', bit_positions=range(32), bit_values=[0] * 6 + [2, 0, 2] + [0] * 23)
    trail = milp.find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(fixed_values=[plaintext, key, key_backward, ciphertext_backward])
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values']['plaintext']['value'] == '00000000000000000000000000000001'
    assert trail['components_values']['intermediate_output_5_12_backward']['value'] == SIMON_INCOMPATIBLE_ROUND_OUTPUT
    assert trail['components_values']['cipher_output_10_13_backward']['value'] == '000000?0?00000000000000000000000'

def test_find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components():
     ascon = AsconSboxSigmaPermutation(number_of_rounds=5)
     milp = MilpBitwiseImpossibleXorDifferentialModel(ascon)
     milp.init_model_in_sage_milp_class()
     plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(320),
                                          bit_values=[1] + [0] * 191 + [1] + [0] * 63 + [1] + [0] * 63)
     P1 = set_fixed_variables(component_id='intermediate_output_0_71', constraint_type='equal',
                                   bit_positions=range(320),
                                   bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0])
     P2 = set_fixed_variables(component_id='intermediate_output_1_71', constraint_type='equal',
                                   bit_positions=range(320),
                                   bit_values=[2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0,
                                               0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 2, 0, 2, 2, 0, 0, 0, 0, 0, 2, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 2, 0, 2, 0, 0, 2, 2,
                                               0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
                                               2, 0, 2, 0, 0, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 0, 0, 2, 2, 2, 0, 0, 0,
                                               2, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                                               2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0,
                                               2, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 2, 0, 2, 2, 2, 0, 2, 0, 0, 2,
                                               0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2,
                                               0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0,
                                               0, 0, 2, 0, 0, 2, 0, 0])
     P3 = set_fixed_variables(component_id='intermediate_output_2_71', constraint_type='equal',
                                   bit_positions=range(320),
                                   bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                                               2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                                               2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2,
                                               2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2,
                                               0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2,
                                               2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                                               2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 2, 2,
                                               2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2,
                                               2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                                               2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0,
                                               2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                                               2, 0, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                                               2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2,
                                               2, 2, 2, 2, 2, 2, 2, 2])
     P5 = set_fixed_variables(component_id='cipher_output_4_71', constraint_type='equal', bit_positions=range(320),
                                   bit_values=[0] * 192 + [1] + [0] * 127)
     trail = milp.find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(["sbox_3_56"],
                                                                                                        fixed_values=[
                                                                                                            plaintext,
                                                                                                            P1, P2, P3,
                                                                                                            P5])
     assert trail['status'] == 'SATISFIABLE'
     assert trail['components_values']['sbox_3_56']['value'] == '00000'
     assert trail['components_values']['sigma_3_69_backward']['value'] == '1000101000101010101010000000001010001000000010101000001010000000'


def test_find_one_bitwise_impossible_xor_differential_trail_model_with_external_solver():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
    milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
                                    bit_values=[0] * 31 + [1])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal',
                                     bit_positions=range(32), bit_values=[0] * 6 + [2, 0, 2] + [0] * 23)
    trail = milp.find_one_bitwise_impossible_xor_differential_trail(6, fixed_values=[plaintext, key, ciphertext], external_solver_name='glpk')
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values']['intermediate_output_5_12']['value'] == '????????????????0??????1??????0?'
    assert trail['components_values']['intermediate_output_5_12_backward']['value'] == SIMON_INCOMPATIBLE_ROUND_OUTPUT


def test_find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model_with_external_solver():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
    milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
                                    bit_values=[0] * 31 + [1])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    key_backward = set_fixed_variables(component_id='key_backward', constraint_type='equal', bit_positions=range(64),
                                       bit_values=[0] * 64)
    ciphertext_backward = set_fixed_variables(component_id='cipher_output_10_13_backward', constraint_type='equal',
                                              bit_positions=range(32), bit_values=[0] * 6 + [2, 0, 2] + [0] * 23)
    trail = milp.find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(
        fixed_values=[plaintext, key, key_backward, ciphertext_backward], external_solver_name='glpk')
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values']['plaintext']['value'] == '00000000000000000000000000000001'
    assert trail['components_values']['intermediate_output_5_12_backward']['value'] == SIMON_INCOMPATIBLE_ROUND_OUTPUT
    assert trail['components_values']['cipher_output_10_13_backward']['value'] == '000000?0?00000000000000000000000'
