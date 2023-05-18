import pytest

from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.milp.milp_model import get_independent_input_output_variables, \
    get_input_output_variables


def test_get_independent_input_output_variables():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    component = speck.get_component_from_id("xor_1_10")
    input_output_variables = get_independent_input_output_variables(component)

    assert len(input_output_variables[0]) == 32
    assert input_output_variables[0][0] == 'xor_1_10_0_i'
    assert input_output_variables[0][1] == 'xor_1_10_1_i'
    assert input_output_variables[0][30] == 'xor_1_10_30_i'
    assert input_output_variables[0][31] == 'xor_1_10_31_i'

    assert len(input_output_variables[1]) == 16
    assert input_output_variables[1][0] == 'xor_1_10_0_o'
    assert input_output_variables[1][1] == 'xor_1_10_1_o'
    assert input_output_variables[1][14] == 'xor_1_10_14_o'
    assert input_output_variables[1][15] == 'xor_1_10_15_o'


def test_get_input_output_variables():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    component = speck.get_component_from_id("rot_0_0")
    input_output_variables = get_input_output_variables(component)

    assert len(input_output_variables[0]) == 16
    assert input_output_variables[0][0] == 'plaintext_0'
    assert input_output_variables[0][1] == 'plaintext_1'
    assert input_output_variables[0][14] == 'plaintext_14'
    assert input_output_variables[0][15] == 'plaintext_15'

    assert len(input_output_variables[1]) == 16
    assert input_output_variables[1][0] == 'rot_0_0_0'
    assert input_output_variables[1][1] == 'rot_0_0_1'
    assert input_output_variables[1][14] == 'rot_0_0_14'
    assert input_output_variables[1][15] == 'rot_0_0_15'


def test_fix_variables_value_constraints():
    simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpModel(simon)
    milp.init_model_in_sage_milp_class()
    fixed_variables = [{'component_id': 'plaintext',
                        'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [1, 0, 1, 1]
                        },
                       {'component_id': 'cipher_output_1_8',
                        'constraint_type': 'not_equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [1, 1, 1, 0]
                        }]
    constraints = milp.fix_variables_value_constraints(fixed_variables)

    assert len(constraints) == 9
    assert str(constraints[0]) == 'x_0 == 1'
    assert str(constraints[1]) == 'x_1 == 0'
    assert str(constraints[2]) == 'x_2 == 1'
    assert str(constraints[3]) == 'x_3 == 1'
    assert str(constraints[4]) == 'x_4 == 1 - x_5'
    assert str(constraints[5]) == 'x_6 == 1 - x_7'
    assert str(constraints[6]) == 'x_8 == 1 - x_9'
    assert str(constraints[7]) == 'x_10 == x_11'
    assert str(constraints[8]) == '1 <= x_4 + x_6 + x_8 + x_10'


def test_model_constraints():
    with pytest.raises(Exception):
        speck = SpeckBlockCipher(number_of_rounds=4)
        milp = MilpModel(speck)
        milp.model_constraints()


def test_solve():
    speck = SpeckBlockCipher(number_of_rounds=4)
    milp = MilpXorDifferentialModel(speck)
    milp.init_model_in_sage_milp_class()
    milp.add_constraints_to_build_in_sage_milp_class()
    differential_solution = milp.solve("xor_differential")

    assert differential_solution['cipher_id'] == 'speck_p32_k64_o32_r4'
    assert differential_solution['model_type'] == 'xor_differential'
    assert differential_solution['components_values']['key']['weight'] == 0
    assert differential_solution['components_values']['key']['sign'] == 1
    assert differential_solution['components_values']['modadd_0_1']['weight'] >= 0
    assert differential_solution['components_values']['modadd_0_1']['sign'] == 1
    assert differential_solution['solver_name'] == 'GLPK'
    assert differential_solution['total_weight'] >= 0.0

    milp = MilpXorLinearModel(speck)
    milp.init_model_in_sage_milp_class()
    milp.add_constraints_to_build_in_sage_milp_class()
    linear_solution = milp.solve("xor_linear")

    assert linear_solution['cipher_id'] == 'speck_p32_k64_o32_r4'
    assert linear_solution['model_type'] == 'xor_linear'
    assert differential_solution['components_values']['key']['weight'] == 0
    assert linear_solution['components_values']['key']['sign'] == 1
    assert linear_solution['components_values']['modadd_1_7_i']['weight'] >= 0
    assert linear_solution['components_values']['modadd_1_7_i']['sign'] == 1
    assert linear_solution['solver_name'] == 'GLPK'
    assert linear_solution['total_weight'] >= 0.0

