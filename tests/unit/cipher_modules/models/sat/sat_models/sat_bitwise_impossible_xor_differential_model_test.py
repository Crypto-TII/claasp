from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import \
    SatBitwiseImpossibleXorDifferentialModel


def test_build_bitwise_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=2)
    sat = SatBitwiseImpossibleXorDifferentialModel(speck)
    sat._forward_cipher = speck.get_partial_cipher(0, 1, keep_key_schedule=True)
    backward_cipher = sat._cipher.cipher_partial_inverse(1, 1, keep_key_schedule=False)
    sat._backward_cipher = backward_cipher.add_suffix_to_components(
        "_backward", [backward_cipher.get_all_components_ids()[-1]])
    sat.build_bitwise_impossible_xor_differential_trail_model()
    constraints = sat.model_constraints

    assert len(constraints) == 2625
    assert constraints[0] == 'rot_0_0_0_0 -plaintext_9_0'
    assert constraints[1] == 'plaintext_9_0 -rot_0_0_0_0'
    assert constraints[-2] == 'intermediate_output_0_6_backward_31_1 -rot_1_9_15_1'
    assert constraints[-1] == 'rot_1_9_15_1 -intermediate_output_0_6_backward_31_1'


def test_find_one_bitwise_deterministic_truncated_xor_differential_trail():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
    sat = SatBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal',
                                                bit_positions=range(32), bit_values=[0]*31 + [1])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
    ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal',
                                     bit_positions=range(32), bit_values=[0]*6 + [2, 0, 2] + [0]*23)
    trail = sat.find_one_bitwise_impossible_xor_differential_trail(6, fixed_values=[plaintext, key, ciphertext])
    assert trail['components_values']['intermediate_output_5_12']['value'] == '????????????????0??????1??????0?'
    assert trail['components_values']['intermediate_output_5_12_backward']['value'] == '????????00?????0???????0????????'

    simon = SimonBlockCipher(block_bit_size=48, key_bit_size=72, number_of_rounds=12)
    sat = SatBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(48),
                                    bit_values=[0]*47 + [1])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(72), bit_values=[0]*72)
    ciphertext = set_fixed_variables(component_id='cipher_output_11_12', constraint_type='equal',
                                     bit_positions=range(48), bit_values=[1]+[0]*16 + [2,0,0,0,2,2,2] + [0]*24)
    trail = sat.find_one_bitwise_impossible_xor_differential_trail(7, fixed_values=[plaintext, key, ciphertext])
    assert trail['components_values']['intermediate_output_6_11']['value'] == '????????????????????????0???????????????????????'
    assert trail['components_values']['intermediate_output_6_11_backward']['value'] == '?00?????0???????????????1???????????????????????'
