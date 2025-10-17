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
                                                get_related_key_scenario_format_for_fixed_values,
                                                differential_truncated_checker_permutation,
                                                differential_checker_permutation,
                                                differential_truncated_checker_permutation_input_and_output_truncated,
                                                differential_truncated_linear_checker_permutation_input_truncated_ouput_mask)
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.ciphers.permutations.salsa_permutation import SalsaPermutation

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

    assert str(solution['cipher']) == 'speck_p32_k64_o32_r4'
    assert solution['total_weight'] == 4.0
    assert solution['measure'] == 'bias'


def test_to_probability_for_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4).remove_key_schedule()
    milp = MilpXorLinearModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type=NOT_EQUAL, bit_positions=range(32),
                                    bit_values=integer_to_bit_list(0x0, 32, 'big'))
    trail = milp.find_lowest_weight_xor_linear_trail([plaintext])
    solution = to_probability_for_xor_linear_trail(speck, trail)

    assert str(solution['cipher']) == 'speck_p32_k64_o32_r4'
    assert solution['measure'] == 'probability'
    assert solution['total_weight'] == 0.83


def test_to_correlation_for_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4).remove_key_schedule()
    milp = MilpXorLinearModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type=NOT_EQUAL,
                                    bit_positions=range(32), bit_values=integer_to_bit_list(0x0, 32, 'big'))
    trail = milp.find_lowest_weight_xor_linear_trail([plaintext])
    solution = to_correlation_for_xor_linear_trail(speck, trail)

    assert str(solution['cipher']) == 'speck_p32_k64_o32_r4'
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


def test_differential_checker_permutation():
    cipher = ChachaPermutation(number_of_rounds=1)
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000
    output_difference = 0x00000000000000000000000000000000800000000000000000000000000000000008000000000000000000000000000000080000000000000000000000000000

    probability_weight = differential_checker_permutation(
        cipher, input_difference, output_difference, 1 << 12, 512, seed=42
    )
    assert abs(probability_weight) < 2


def test_differential_truncated_checker_permutation():
    cipher = ChachaPermutation(number_of_rounds=3)
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000
    output_difference = '100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000????????????????????????????????????????????????????????????????????1000000000000000????????????????????100000000000????????????????????????10000000????????????????????????????????????10000000????????????????????????????????????????????????1000000000000000????????????????????1000000000000000000010000000000010000000000000000000000000000000000000000000????????????????????????????????00000000000000001000000000000000'

    probability_weight = differential_truncated_checker_permutation(
        cipher, input_difference, output_difference, 1 << 12, 512, seed=42
    )
    assert abs(probability_weight) < 2

def test_differential_truncated_checker_permutation():
    cipher = ChachaPermutation(number_of_rounds=3)
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000
    output_difference = '100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000????????????????????????????????????????????????????????????????????1000000000000000????????????????????100000000000????????????????????????10000000????????????????????????????????????10000000????????????????????????????????????????????????1000000000000000????????????????????1000000000000000000010000000000010000000000000000000000000000000000000000000????????????????????????????????00000000000000001000000000000000'

    probability_weight = differential_truncated_checker_permutation(
        cipher, input_difference, output_difference, 1 << 12, 512, seed=42
    )
    assert abs(probability_weight) < 2


def test_differential_truncated_checker_permutation_input_and_output_truncated():
    chachaPermutation = ChachaPermutation(number_of_rounds=5, start_round=("even", "top"))
    chachaPermutation_inv = chachaPermutation.cipher_inverse()
    # TODO: 
    # - check the following backward truncated differential. 
    # - this backward distinguisher covers 2.5 rounds of ChaCha (5 half rounds).
    # - this backward distinguisher starts at the 7.5 round of ChaCha and ends at the 5th round of ChaCha. 
    # - this distinguihser was found using MiniZinc semi-deterministic model (check correctness). You can add more distinguishers to increase confidence.
    # ================================================Distinguisher X_backward_0===================================================
    # Theoretical cost:  1.47
    # Input_diff for (X_backward_0)
    # 20220000022001201120202222222200 | 20100202202211222200011200222002 | 00002020202021000000000022200020 | 20020120010110001010100011010000
    # 22222222222222222222222222222222 | 22222222222222222222222222222222 | 02222222222210222222222220222222 | 22200000000022222221222222222222
    # 22222222222222200000000022222221 | 22222222222222222222222222222222 | 00002222222210000000000000000000 | 22222122222202222222222210222222
    # 22201210121022202022222121200020 | 10222011210122000200000001021001 | 10101000110100000020122110011000 | 10000200222000000000000000000000
    # Output_diff for (X_backwards_0)
    # 22222222222222222222222222222222 | 22222222222222222222222222222222 | 22222222222222222222222222222220 | 22222222222222222222222222222222
    # 22222222222222222222222222222222 | 22222222222222222222222222222222 | 22222222222202222222222202222220 | 22222222222222222222222222222222
    # 22222222222222222222222222222222 | 22222222222222222222222222222222 | 22222222222222220100222222222220 | 22222222222222222222222222222222
    # 22222222222222222222222222222222 | 22222222222222222222222222222222 | 22222222222222222222222222222221 | 22222222222222222222222222222222
    
    input_trunc_diff = "" #TODO: add input trunc diff 
    output_trunc_diff = "" #TODO: add output trunc diff
    number_of_samples = 1 << 19
    state_size = 512
    prob = differential_truncated_checker_permutation_input_and_output_truncated(
        chachaPermutation_inv,
        input_trunc_diff, 
        output_trunc_diff,
        number_of_samples,
        state_size,
        seed=None,
    )
    print(prob)
    #import ipdb; ipdb.set_trace()


# TODO: Add test for differential_truncated_linear_checker_permutation_input_truncated_ouput_mask
def test_differential_truncated_linear_checker_permutation_input_truncated_ouput_mask():
    # TODO: Implement test
    return 0
