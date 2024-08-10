from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import \
    MznImpossibleXorDifferentialModel


def test_build_impossible_xor_differential_trail_with_extensions_model():
    speck = SpeckBlockCipher(number_of_rounds=6)
    mzn = MznImpossibleXorDifferentialModel(speck)
    fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
    mzn.build_impossible_xor_differential_trail_with_extensions_model(number_of_rounds=6, fixed_variables=fixed_variables, initial_round=2, middle_round=3, final_round=5, intermediate_components=False)

    assert len(mzn.model_constraints) == 1764
    assert mzn.model_constraints[99] == 'array[0..31] of var 0..2: inverse_plaintext;'
    assert mzn.model_constraints[3] == 'array[0..63] of var 0..2: key;'
    assert mzn.model_constraints[39] == 'array[0..31] of var 0..2: cipher_output_5_12;'


def test_build_impossible_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=5)
    mzn = MznImpossibleXorDifferentialModel(speck)
    fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
    mzn.build_impossible_xor_differential_trail_model(number_of_rounds=5, fixed_variables=fixed_variables, middle_round=3)

    assert len(mzn.model_constraints) == 1662
    assert mzn.model_constraints[2] == 'array[0..31] of var 0..2: plaintext;'
    assert mzn.model_constraints[3] == 'array[0..63] of var 0..2: key;'
    assert mzn.model_constraints[4] == 'array[0..31] of var 0..2: inverse_cipher_output_4_12;'


def test_find_all_impossible_xor_differential_trails():
    speck = SpeckBlockCipher(number_of_rounds=7)
    mzn = MznImpossibleXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    ciphertext = set_fixed_variables(component_id='inverse_' + speck.get_all_components_ids()[-1], constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    key = set_fixed_variables('key', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    trail = mzn.find_all_impossible_xor_differential_trails(7, [plaintext, ciphertext, key], 'Chuffed', 1, 3, 7, False, solve_external = True)

    assert trail[0]['status'] == 'UNSATISFIABLE'


def test_find_lowest_complexity_impossible_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=6)
    mzn = MznImpossibleXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    ciphertext = set_fixed_variables(component_id='inverse_' + speck.get_all_components_ids()[-1], constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    key = set_fixed_variables('key', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    trail = mzn.find_lowest_complexity_impossible_xor_differential_trail(6, [plaintext, ciphertext, key], 'Chuffed', 1, 3, 6, True, solve_external = True)

    assert str(trail['cipher']) == 'speck_p32_k64_o32_r6'
    assert trail['model_type'] == 'impossible_xor_differential_one_solution'
    assert trail['solver_name'] == 'Chuffed'

    assert trail['components_values']['plaintext']['value'] == '00000000010000000000000000000000'
    assert trail['components_values']['inverse_cipher_output_5_12']['value'] == '10000000000000001000000000000010'
    
    assert trail['components_values']['xor_1_10']['value'] == '2222222100000010'
    assert trail['components_values']['inverse_rot_2_9']['value'] == '2222222210022222'


def test_find_one_impossible_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=6)
    mzn = MznImpossibleXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    ciphertext = set_fixed_variables(component_id='inverse_' + speck.get_all_components_ids()[-1], constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    key = set_fixed_variables('key', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    trail = mzn.find_one_impossible_xor_differential_trail(6, [plaintext, ciphertext, key], 'Chuffed', 1, 3, 6, True, solve_external = True)

    assert str(trail['cipher']) == 'speck_p32_k64_o32_r6'
    assert trail['model_type'] == 'impossible_xor_differential_one_solution'
    assert trail['solver_name'] == 'Chuffed'

    assert trail['components_values']['plaintext']['value'] == '00000000022200000021000000000000'
    assert trail['components_values']['inverse_cipher_output_5_12']['value'] == '10000000000000001000000000000010'
    
    assert trail['components_values']['xor_1_10']['value'] == '2222222222100022'
    assert trail['components_values']['inverse_rot_2_9']['value'] == '2222222210022222'


def test_find_one_impossible_xor_differential_trail_with_extensions():
    speck = SpeckBlockCipher(number_of_rounds=6)
    mzn = MznImpossibleXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='inverse_plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    ciphertext = set_fixed_variables(component_id=speck.get_all_components_ids()[-1], constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    key = set_fixed_variables('key', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    trail = mzn.find_one_impossible_xor_differential_trail_with_extensions(6, [plaintext, ciphertext, key], 'Chuffed', 2, 3, 5, True, solve_external = True)

    assert str(trail['cipher']) == 'speck_p32_k64_o32_r6'
    assert trail['model_type'] == 'impossible_xor_differential_one_solution'
    assert trail['solver_name'] == 'Chuffed'
    
    assert trail['components_values']['inverse_plaintext']['value'] == '22222220022222220000100000022200'
    assert trail['components_values']['inverse_cipher_output_5_12']['value'] == '22222210000000002222221000000011'
    
    assert trail['components_values']['intermediate_output_2_12']['value'] == '22222222220000002222222222000022'
    assert trail['components_values']['inverse_intermediate_output_2_12']['value'] == '22222222222222222222222222122222'
