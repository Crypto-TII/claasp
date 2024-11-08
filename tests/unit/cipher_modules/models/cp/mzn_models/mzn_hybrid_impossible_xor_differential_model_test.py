from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import \
    MznHybridImpossibleXorDifferentialModel
from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list


def test_build_impossible_xor_differential_trail_model():
    lblock = LBlockBlockCipher(number_of_rounds=4)
    mzn = MznHybridImpossibleXorDifferentialModel(lblock)
    fixed_variables = [set_fixed_variables('key', 'equal', range(80), [0]*80)]
    mzn.build_hybrid_impossible_xor_differential_trail_model(number_of_rounds=4, fixed_variables=fixed_variables, middle_round=3)

    assert len(mzn.model_constraints) == 2442
    assert mzn.model_constraints[2] == 'set of int: ext_domain = 0..2 union { i | i in 10..800 where (i mod 10 = 0)};'
    assert mzn.model_constraints[3] == 'array[0..63] of var ext_domain: plaintext;'
    assert mzn.model_constraints[4] == 'array[0..79] of var ext_domain: key;'
    assert mzn.model_constraints[5] == 'array[0..63] of var ext_domain: inverse_cipher_output_3_19;'


def test_find_all_impossible_xor_differential_trails():
    lblock = LBlockBlockCipher(number_of_rounds=4)
    mzn = MznHybridImpossibleXorDifferentialModel(lblock)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    ciphertext = set_fixed_variables(component_id='inverse_' + lblock.get_all_components_ids()[-1], constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    key = set_fixed_variables('key', constraint_type='equal',
                                    bit_positions=range(78), bit_values=[0] * 78)
    trails = mzn.find_all_impossible_xor_differential_trails(4, [plaintext, ciphertext, key], 'Chuffed', 1, 3, 4, False, solve_external=True)
    assert len(trails) == 6
    assert trails[0]['status'] == 'SATISFIABLE'
    assert trails[0]['components_values']['plaintext'][
               'value'] == '................................................................'
    assert trails[0]['components_values']['inverse_cipher_output_3_19'][
               'value'] == '................................................................'

def test_find_all_improbable_xor_differential_trails():
    lblock = LBlockBlockCipher(number_of_rounds=4)
    mzn = MznHybridImpossibleXorDifferentialModel(lblock)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    ciphertext = set_fixed_variables(component_id='inverse_' + lblock.get_all_components_ids()[-1], constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(80),
                              bit_values=[0]*10+[1]+[0]*69)
    trails = mzn.find_all_impossible_xor_differential_trails(4, [plaintext, ciphertext, key], 'Chuffed', 1, 3, 4, False,
                                                             probabilistic=True, solve_external=True)
    assert trails['total_weight'] == 0.0
    assert len(trails['solutions']) == 6
    assert trails['solutions'][0]['status'] == 'SATISFIABLE'
    assert trails['solutions'][0]['components_values']['plaintext'][
               'value'] == '................................................................'
    assert trails['solutions'][0]['components_values']['inverse_cipher_output_3_19'][
               'value'] == '................................................................'

def test_find_one_impossible_xor_differential_trail():
    lblock = LBlockBlockCipher(number_of_rounds=4)
    mzn = MznHybridImpossibleXorDifferentialModel(lblock)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    ciphertext = set_fixed_variables(component_id='inverse_' + lblock.get_all_components_ids()[-1],
                                     constraint_type='equal',
                                     bit_positions=range(64), bit_values=[0] * 64)
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(80),
                              bit_values=[0] * 10 + [1] + [0] * 69)
    trail = mzn.find_one_impossible_xor_differential_trail(4, [plaintext, ciphertext, key], 'Chuffed', 1, 3, 4, False, solve_external = True)

    assert str(trail['cipher']) == 'lblock_p64_k80_o64_r4'
    assert trail['model_type'] == 'impossible_xor_differential_one_solution'
    assert trail['solver_name'] == 'Chuffed'

    assert trail['components_values']['plaintext']['value'] == '................................................................'
    assert trail['components_values']['inverse_cipher_output_3_19']['value'] == '................................................................'
    assert trail['status'] == 'SATISFIABLE'

def test_find_one_improbable_xor_differential_trail():
    lblock = LBlockBlockCipher(number_of_rounds=4)
    mzn = MznHybridImpossibleXorDifferentialModel(lblock)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal',
                                    bit_positions=range(64), bit_values=[0] * 64)
    ciphertext = set_fixed_variables(component_id='inverse_' + lblock.get_all_components_ids()[-1],
                                     constraint_type='equal',
                                     bit_positions=range(64), bit_values=[0] * 64)
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(80),
                              bit_values=[0] * 10 + [1] + [0] * 69)
    trail = mzn.find_one_impossible_xor_differential_trail(4, [plaintext, ciphertext, key], 'Chuffed', 1, 3, 4, False,
                                                           probabilistic=True, solve_external=True)

    assert str(trail['cipher']) == 'lblock_p64_k80_o64_r4'
    assert trail['model_type'] == 'impossible_xor_differential_one_solution'
    assert trail['solver_name'] == 'Chuffed'

    assert trail['components_values']['plaintext'][
               'value'] == '................................................................'
    assert trail['components_values']['inverse_cipher_output_3_19'][
               'value'] == '................................................................'
    assert float(trail['total_weight']) in [2.0, 3.0]
