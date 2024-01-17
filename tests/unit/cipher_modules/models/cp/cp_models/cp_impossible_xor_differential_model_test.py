from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.cp.cp_models.cp_impossible_xor_differential_model import \
    CpImpossibleXorDifferentialModel


def test_build_impossible_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=5)
    cp = CpImpossibleXorDifferentialModel(speck)
    fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
    cp.build_impossible_xor_differential_trail_model(number_of_rounds=5, fixed_variables=fixed_variables, middle_round=3)

    assert len(cp.model_constraints) == 1566
    assert cp.model_constraints[2] == 'array[0..31] of var 0..2: plaintext;'
    assert cp.model_constraints[3] == 'array[0..63] of var 0..2: key;'
    assert cp.model_constraints[4] == 'array[0..31] of var 0..2: inverse_cipher_output_4_12;'


def find_all_impossible_xor_differential_trails():
    speck = SpeckBlockCipher(number_of_rounds=7)
    cp = CpImpossibleXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    ciphertext = set_fixed_variables(component_id='inverse_' + speck.get_all_components_ids()[-1], constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    key = set_fixed_variables('key', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    trail = cp.find_all_impossible_xor_differential_trails(7, [plaintext, ciphertext, key], 'Chuffed', 3)

    assert trail[0]['status'] == 'UNSATISFIABLE'


def find_one_impossible_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=6)
    cp = CpImpossibleXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    ciphertext = set_fixed_variables(component_id='inverse_' + speck.get_all_components_ids()[-1], constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    key = set_fixed_variables('key', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    trail = cp.find_one_impossible_xor_differential_trail(6, [plaintext, ciphertext, key], 'Chuffed', 3)

    assert trail['cipher_id'] == 'speck_p32_k64_o32_r6'
    assert trail['model_type'] == 'impossible_xor_differential_one_solution'
    assert trail['solver_name'] == 'Chuffed'

    assert trail['components_values']['plaintext']['value'] == '00000000022200000021000000000000'
    assert trail['components_values']['inverse_cipher_output_5_12']['value'] == '10000000000000001000000000000010'
    
    assert trail['components_values']['xor_1_10']['value'] == '2222222222100022'
    assert trail['components_values']['inverse_rot_2_9']['value'] == '2222222210022222'
