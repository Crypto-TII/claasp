import os
import sys
from io import StringIO

from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import (convert_solver_solution_to_dictionary, integer_to_bit_list,
                                                set_fixed_variables, to_bias_for_xor_linear_trail,
                                                to_probability_for_xor_linear_trail,
                                                to_correlation_for_xor_linear_trail,
                                                find_sign_for_xor_linear_trails, print_components_values,
                                                write_solution_to_file,
                                                get_single_key_scenario_format_for_fixed_values,
                                                get_related_key_scenario_format_for_fixed_values)

NOT_EQUAL = 'not equal'


def test_print_components_values():
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    print_components_values({'components_values': {
        'plaintext': {
            'value': '0x1234',
            'weight': 0},
        'key': {
            'value': '0xabcd',
            'weight': 7}}})
    sys.stdout = old_stdout

    assert result.getvalue() == f"┌───────────────────────────┬──────────────────────────────────────────┬────────┐\n" \
                                f"│ COMPONENT ID              │ VALUE                                    │ WEIGHT │\n" \
                                f"├───────────────────────────┼──────────────────────────────────────────┼────────┤\n" \
                                f"│ plaintext                 │ 0x1234                                   │ -      │\n" \
                                f"├───────────────────────────┼──────────────────────────────────────────┼────────┤\n" \
                                f"│ key                       │ 0xabcd                                   │ 7      │\n" \
                                f"└───────────────────────────┴──────────────────────────────────────────┴────────┘\n"


def test_write_solution_to_file():
    speck = SpeckBlockCipher(number_of_rounds=4)
    file_name = 'claasp/previous_results/speck/sat/speck32_64_r22_cryptominisat.py'
    solution = convert_solver_solution_to_dictionary(speck.id, 'xor_differential', 'z3', 0.239, 175.5, [], 0)
    write_solution_to_file(solution, file_name)
    assert os.path.isfile(file_name)
    os.remove(file_name)


def test_to_bias_for_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4).remove_key_schedule()
    milp = MilpXorLinearModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type=NOT_EQUAL,
                                    bit_positions=range(32), bit_values=integer_to_bit_list(0x0, 32, 'big'))
    trail = milp.find_lowest_weight_xor_linear_trail([plaintext])
    solution = to_bias_for_xor_linear_trail(speck, trail)

    assert solution['cipher_id'] == 'speck_p32_k64_o32_r4'
    assert solution['total_weight'] == 4.0
    assert solution['measure'] == 'bias'


def test_to_probability_for_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4).remove_key_schedule()
    milp = MilpXorLinearModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type=NOT_EQUAL, bit_positions=range(32),
                                    bit_values=integer_to_bit_list(0x0, 32, 'big'))
    trail = milp.find_lowest_weight_xor_linear_trail([plaintext])
    solution = to_probability_for_xor_linear_trail(speck, trail)

    assert solution['cipher_id'] == 'speck_p32_k64_o32_r4'
    assert solution['measure'] == 'probability'
    assert solution['total_weight'] == 0.83


def test_to_correlation_for_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4).remove_key_schedule()
    milp = MilpXorLinearModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type=NOT_EQUAL,
                                    bit_positions=range(32), bit_values=integer_to_bit_list(0x0, 32, 'big'))
    trail = milp.find_lowest_weight_xor_linear_trail([plaintext])
    solution = to_correlation_for_xor_linear_trail(speck, trail)

    assert solution['cipher_id'] == 'speck_p32_k64_o32_r4'
    assert solution['measure'] == 'correlation'
    assert solution['total_weight'] == 3.0


def test_find_sign_for_xor_linear_trails():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3).remove_key_schedule()
    milp = MilpXorLinearModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type=NOT_EQUAL,
                                    bit_positions=range(8), bit_values=integer_to_bit_list(0x0, 8, 'big'))
    trails = milp.find_all_xor_linear_trails_with_fixed_weight(1, fixed_values=[plaintext])
    trails_with_sign = find_sign_for_xor_linear_trails(speck, trails)

    assert abs(trails_with_sign[0]['final_sign']) == 1


def test_get_related_key_scenario_format_for_fixed_values():
    speck = SpeckBlockCipher(number_of_rounds=4)
    fixed_values = get_related_key_scenario_format_for_fixed_values(speck)
    assert fixed_values[0]["constraint_type"] == 'not_equal'


def test_get_single_key_scenario_format_for_fixed_values():
    speck = SpeckBlockCipher(number_of_rounds=4)
    fixed_values = get_single_key_scenario_format_for_fixed_values(speck)
    assert fixed_values[0]["constraint_type"] == 'equal'
    assert fixed_values[1]["constraint_type"] == 'not_equal'
