from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel


def test_branch_xor_linear_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorLinearModel(speck)
    constraints = sat.branch_xor_linear_constraints()

    assert constraints[0] == '-plaintext_0_o rot_0_0_0_i'
    assert constraints[1] == 'plaintext_0_o -rot_0_0_0_i'
    assert constraints[2] == '-plaintext_1_o rot_0_0_1_i'
    assert constraints[-3] == 'xor_2_10_14_o -cipher_output_2_12_30_i'
    assert constraints[-2] == '-xor_2_10_15_o cipher_output_2_12_31_i'
    assert constraints[-1] == 'xor_2_10_15_o -cipher_output_2_12_31_i'

def test_find_all_xor_linear_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
    sat = SatXorLinearModel(speck)
    key = set_fixed_variables('key', 'not_equal', list(range(16)), [0] * 16)
    trails = sat.find_all_xor_linear_trails_with_weight_at_most(0, 3, fixed_values=[key])

    assert len(trails) == 73


def test_find_lowest_weight_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    sat = SatXorLinearModel(speck)
    trail = sat.find_lowest_weight_xor_linear_trail()

    assert trail['total_weight'] == 3.0


def test_find_one_xor_linear_trail():
    speck = SpeckBlockCipher(number_of_rounds=4)
    sat = SatXorLinearModel(speck)
    trail = sat.find_one_xor_linear_trail()

    assert str(trail['cipher']) == 'speck_p32_k64_o32_r4'
    assert trail['model_type'] == 'xor_linear'
    assert trail['solver_name'] == 'cryptominisat'
    assert trail['status'] == 'SATISFIABLE'


def test_find_one_xor_linear_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorLinearModel(speck)
    result = sat.find_one_xor_linear_trail_with_fixed_weight(7)

    assert result['total_weight'] == 7.0


def test_fix_variables_value_xor_linear_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorLinearModel(speck)
    fixed_variables = [{'component_id': 'plaintext',
                        'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [1, 0, 1, 1]},
                       {'component_id': 'ciphertext',
                        'constraint_type': 'not_equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [1, 1, 1, 0]}]
    constraints = sat.fix_variables_value_xor_linear_constraints(fixed_variables)

    assert constraints == ['plaintext_0_o', '-plaintext_1_o', 'plaintext_2_o', 'plaintext_3_o',
                           '-ciphertext_0_o -ciphertext_1_o -ciphertext_2_o ciphertext_3_o']
