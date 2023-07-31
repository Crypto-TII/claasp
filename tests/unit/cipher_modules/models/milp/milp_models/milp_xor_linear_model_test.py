from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
import pytest

def test_build_xor_linear_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    milp = MilpXorLinearModel(speck)
    milp.init_model_in_sage_milp_class()
    milp.build_xor_linear_trail_model()

    assert str(milp.model_constraints[0]) == 'x_16 == x_9'
    assert str(milp.model_constraints[1]) == 'x_17 == x_10'
    assert str(milp.model_constraints[2]) == 'x_18 == x_11'
    assert str(milp.model_constraints[23759]) == 'x_12127 == x_12191'
    assert str(milp.model_constraints[23760]) == 'x_12128 == x_12192'


def test_find_all_xor_linear_trails_with_fixed_weight():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3)
    milp = MilpXorLinearModel(speck.remove_key_schedule())
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not equal',
                                    bit_positions=range(8), bit_values=integer_to_bit_list(0x0, 8, 'big'))
    trails = milp.find_all_xor_linear_trails_with_fixed_weight(1, fixed_values=[plaintext])

    assert len(trails) == 12
    for i in range(len(trails)):
        assert trails[i]['cipher_id'] == 'speck_p8_k16_o8_r3'
        assert trails[i]['total_weight'] == 1.0
        assert eval(trails[i]['components_values']['plaintext']['value']) > 0
        assert eval(trails[i]['components_values']['key_0_2']['value']) >= 0
        assert trails[i]['components_values']['key_0_2']['weight'] == 0
        assert trails[i]['components_values']['key_0_2']['sign'] == 1
        assert eval(trails[i]['components_values']['rot_0_0_i']['value']) >= 0
        assert trails[i]['components_values']['rot_0_0_i']['weight'] == 0
        assert trails[i]['components_values']['rot_0_0_i']['sign'] == 1


def test_find_all_xor_linear_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3)
    milp = MilpXorLinearModel(speck.remove_key_schedule())
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not equal',
                                    bit_positions=range(8), bit_values=integer_to_bit_list(0x0, 8, 'big'))
    trails = milp.find_all_xor_linear_trails_with_weight_at_most(0, 1, [plaintext])

    assert len(trails) == 13
    for i in range(len(trails)):
        assert trails[i]['cipher_id'] == 'speck_p8_k16_o8_r3'
        assert trails[i]['total_weight'] <= 1.0
        assert trails[i]['total_weight'] >= 0.0
        assert eval(trails[i]['components_values']['plaintext']['value']) > 0
        assert eval(trails[i]['components_values']['key_0_2']['value']) >= 0
        assert trails[i]['components_values']['key_0_2']['weight'] == 0
        assert trails[i]['components_values']['key_0_2']['sign'] == 1
        assert eval(trails[i]['components_values']['rot_0_0_i']['value']) >= 0
        assert trails[i]['components_values']['rot_0_0_i']['weight'] == 0
        assert trails[i]['components_values']['rot_0_0_i']['sign'] == 1


def test_find_lowest_weight_xor_linear_trail():
    # speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=9)
    # milp = MilpXorLinearModel(speck.remove_key_schedule())
    # plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
    #                                 bit_values=integer_to_bit_list(0x03805224, 32, 'big'))
    # trail = milp.find_lowest_weight_xor_linear_trail(fixed_values=[plaintext])
    # assert trail["total_weight"] == 14.0

    # simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=13)
    # milp = MilpXorLinearModel(simon.remove_key_schedule())
    # plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
    #                                 bit_values=integer_to_bit_list(0x00200000, 32, 'big'))
    # trail = milp.find_lowest_weight_xor_linear_trail(fixed_values=[plaintext])
    # assert trail["total_weight"] == 18.0
    #
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
    milp = MilpXorLinearModel(speck.remove_key_schedule())
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not equal', bit_positions=range(32),
                                    bit_values=integer_to_bit_list(0x0, 32, 'big'))
    trail = milp.find_lowest_weight_xor_linear_trail(fixed_values=[plaintext])
    assert trail["total_weight"] == 1.0
    #
    # present = PresentBlockCipher(number_of_rounds=3)
    # milp = MilpXorLinearModel(present.remove_key_schedule())
    # plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(64),
    #                                 bit_values=integer_to_bit_list(0x0d00000000000000, 64, 'big'))
    # trail = milp.find_lowest_weight_xor_linear_trail(fixed_values=[plaintext])
    # assert trail["total_weight"] == 4.0


def test_find_one_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorLinearModel(speck.remove_key_schedule())
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
                                    bit_values=integer_to_bit_list(0x03805224, 32, 'big'))
    trail = milp.find_one_xor_linear_trail(fixed_values=[plaintext])
    assert trail["total_weight"] >= 3.0


def test_find_one_xor_linear_trail_with_fixed_weight():
    # speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    # milp = MilpXorLinearModel(speck.remove_key_schedule())
    # trail = milp.find_one_xor_linear_trail_with_fixed_weight(6)
    # assert len(trail) == 9
    # assert trail["total_weight"] == 6.0

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorLinearModel(speck.remove_key_schedule())
    trail = milp.find_one_xor_linear_trail_with_fixed_weight(1)
    assert len(trail) == 9
    assert trail["total_weight"] == 1.0
    #
    # speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    # milp = MilpXorLinearModel(speck.remove_key_schedule())
    # trail = milp.find_one_xor_linear_trail_with_fixed_weight(10)
    # assert len(trail) == 9
    # assert trail["total_weight"] == 10.0


def test_find_one_xor_linear_trail_with_fixed_weight_with_external_solver():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorLinearModel(speck.remove_key_schedule())
    trail = milp.find_one_xor_linear_trail_with_fixed_weight(1, external_solver_name="glpk")
    assert len(trail) == 9
    assert trail["total_weight"] == 1.0


def test_find_one_xor_linear_trail_with_fixed_weight_with_supported_but_not_installed_external_solver():
    with pytest.raises(Exception) as e_info:
        speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
        milp = MilpXorLinearModel(speck.remove_key_schedule())
        trail = milp.find_one_xor_linear_trail_with_fixed_weight(1, external_solver_name="cplex")


def test_find_one_xor_linear_trail_with_fixed_weight_with_installed_external_solver_but_missing_license():
    with pytest.raises(Exception) as e_info:
        speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
        milp = MilpXorLinearModel(speck.remove_key_schedule())
        trail = milp.find_one_xor_linear_trail_with_fixed_weight(1, external_solver_name="Gurobi")

def test_find_one_xor_linear_trail_with_fixed_weight_with_unsupported_external_solver():
    with pytest.raises(Exception) as e_info:
        speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
        milp = MilpXorLinearModel(speck.remove_key_schedule())
        trail = milp.find_one_xor_linear_trail_with_fixed_weight(1, external_solver_name="unsupported_solver")


def test_fix_variables_value_xor_linear_constraints():
    simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorLinearModel(simon)
    milp.init_model_in_sage_milp_class()
    fixed_variables = [{'component_id': 'plaintext',
                        'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [1, 0, 1, 1]
                        }, {'component_id': 'cipher_output_1_8',
                            'constraint_type': 'not_equal',
                            'bit_positions': [0, 1, 2, 3],
                            'bit_values': [1, 1, 1, 0]
                            }]
    constraints = milp.fix_variables_value_xor_linear_constraints(fixed_variables)

    assert str(constraints[0]) == 'x_0 == 1'
    assert str(constraints[1]) == 'x_1 == 0'
    assert str(constraints[7]) == 'x_10 == x_11'
    assert str(constraints[8]) == '1 <= x_4 + x_6 + x_8 + x_10'
