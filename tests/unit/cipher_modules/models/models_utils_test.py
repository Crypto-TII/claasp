import math
import os
import sys
from io import StringIO
import pickle
import numpy as np
import pytest

from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import (convert_solver_solution_to_dictionary, differential_linear_checker_for_block_cipher_single_key, truncated_differential_linear_checker_permutation, integer_to_bit_list,
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
                                                hex_to_bitlist,
                                                linear_checker_for_block_cipher_single_key,
                                                add_arcs,
                                                check_if_implemented_component,
                                                get_previous_output_bit_ids,
                                                set_component_value_weight_sign,
                                                set_component_solution,
                                                join_and_sanitize_strings,
                                                write_model_to_file,
                                                differential_truncated_checker_single_key,
                                                _sample_truncated_difference_from_string)
from claasp.ciphers.permutations.chacha_permutation import ROUND_MODE_HALF, ChachaPermutation
from claasp.ciphers.permutations.salsa_permutation import SalsaPermutation
from claasp.name_mappings import INTERMEDIATE_OUTPUT, WORD_OPERATION

NOT_EQUAL = 'not equal'

class DummyIdentityBlockCipher:
    def evaluate_vectorized(self, inputs):
        return [inputs[0]]


def test_hex_to_bitlist():
    assert hex_to_bitlist("0xabc10") == hex_to_bitlist("0Xabc10")
    assert hex_to_bitlist("0xabc10") == [1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]


def test_set_component_solution_helpers():
    assert set_component_value_weight_sign("0xab", 3, -1) == {"value": "0xab", "weight": 3, "sign": -1}
    assert set_component_solution("abcd") == {"value": "abcd"}
    assert set_component_solution("abcd", weight=2, sign=1) == {"value": "abcd", "weight": 2, "sign": 1}


def test_sample_truncated_difference_from_string_validation_and_bits():
    rng = np.random.default_rng(0)
    with pytest.raises(ValueError, match="pattern length"):
        _sample_truncated_difference_from_string("01", 2, 8, rng)
    with pytest.raises(ValueError, match="may only contain"):
        _sample_truncated_difference_from_string("0A000000", 2, 8, rng)

    samples = _sample_truncated_difference_from_string("10??????", 16, 8, np.random.default_rng(1))
    assert samples.shape == (1, 16)
    assert np.all((samples[0] & 0b10000000) == 0b10000000)
    assert np.all((samples[0] & 0b01000000) == 0)


def test_parallel_and_validation_paths_for_checker_helpers():
    cipher = DummyIdentityBlockCipher()

    corr_seq = differential_linear_checker_for_block_cipher_single_key(
        cipher, 0, "10000000", 32, 8, 8, 0, seed=7, num_workers=1
    )
    corr_par = differential_linear_checker_for_block_cipher_single_key(
        cipher, 0, "10000000", 32, 8, 8, 0, seed=7, num_workers=2
    )
    assert -1.0 <= corr_seq <= 1.0
    assert -1.0 <= corr_par <= 1.0

    lin_corr_par = linear_checker_for_block_cipher_single_key(
        cipher, "00000000", "00000000", 32, 8, 8, 0, seed=5, num_workers=2
    )
    assert lin_corr_par == 1.0

    prob_weight = differential_truncated_checker_single_key(
        cipher, 0, "00000000", 32, 8, 0, 8, seed=3, num_workers=2
    )
    assert math.isfinite(prob_weight)
    assert prob_weight <= 0.0

    impossible = differential_truncated_checker_permutation(
        cipher, 0, "11111111", 32, 8, seed=9, num_workers=2
    )
    assert impossible <= 0.0

    with pytest.raises(ValueError, match="State size must be a multiple of 8"):
        differential_checker_permutation(cipher, 0, 0, 8, 7)
    

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
    cipher = ChachaPermutation(number_of_rounds=1, round_mode=ROUND_MODE_HALF)
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000
    output_difference = 0x00000000000000000000000000000000800000000000000000000000000000000008000000000000000000000000000000080000000000000000000000000000

    probability_weight = differential_checker_permutation(
        cipher, input_difference, output_difference, 1 << 12, 512, seed=42
    )
    assert abs(probability_weight) < 2


def test_differential_truncated_checker_permutation():
    cipher = ChachaPermutation(number_of_rounds=3, round_mode=ROUND_MODE_HALF)
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000
    output_difference = '100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000????????????????????????????????????????????????????????????????????1000000000000000????????????????????100000000000????????????????????????10000000????????????????????????????????????10000000????????????????????????????????????????????????1000000000000000????????????????????1000000000000000000010000000000010000000000000000000000000000000000000000000????????????????????????????????00000000000000001000000000000000'
    input_difference = format(input_difference, "0512b") 
    probability_weight = differential_truncated_checker_permutation_input_and_output_truncated(
        cipher, input_difference, output_difference, 1 << 12, 512, seed=42
    )
    assert abs(probability_weight) < 2


def test_differential_truncated_checker_permutation_input_and_output_truncated_inv():
    """
    Test the following backward truncated differential.
    
    This backward distinguisher covers 2.5 rounds of ChaCha (5 half rounds).
    This backward distinguisher starts at the 7.5 round of ChaCha and ends at the 5th round of ChaCha.
    This distinguisher was found using MiniZinc semi-deterministic model. You can add more distinguishers to increase confidence.
    
    Theoretical cost: 1.47
    """
    input_trunc_diff = "".join((
        f"20220000022001201120202222222200201002022022112222000112002220020000202020202100000000002220002020020120010110001010100011010000",
        f"22222222222222222222222222222222222222222222222222222222222222220222222222221022222222222022222222200000000022222221222222222222",
        f"22222222222222200000000022222221222222222222222222222222222222220000222222221000000000000000000022222122222202222222222210222222",
        f"22201210121022202022222121200020102220112101220002000000010210011010100011010000002012211001100010000200222000000000000000000000"
    ))
    output_trunc_diff = "".join((
        f"22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222022222222222222222222222222222222",
        f"22222222222222222222222222222222222222222222222222222222222222222222222222220222222222220222222022222222222222222222222222222222",
        f"22222222222222222222222222222222222222222222222222222222222222222222222222222222010022222222222022222222222222222222222222222222",
        f"22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222122222222222222222222222222222222"
    ))
    number_of_samples = 1 << 12
    state_size = 512
    chachaPermutation = ChachaPermutation(number_of_rounds=5, start_round=("even", "top"))
    inv_pickle_path = "tests/unit/cipher_modules/models/chacha_permutation_inv_5_rounds.pkl"
    # first check if path exists, if not compute the inverse and save it to a pickle file for faster loading in the future.
    if not os.path.isfile(inv_pickle_path):
        chachaPermutation_inv = chachaPermutation.cipher_inverse()
        with open(inv_pickle_path, "wb") as f:
            pickle.dump(chachaPermutation_inv, f)
    else:
        with open(inv_pickle_path, "rb") as f:
            chachaPermutation_inv = pickle.load(f)
    prob = differential_truncated_checker_permutation_input_and_output_truncated(
        chachaPermutation_inv,
        input_trunc_diff,
        output_trunc_diff,
        number_of_samples,
        state_size,
        seed=42,  # Use same seed as pattern generation
    )
    assert math.isfinite(prob)
    observed_probability = 2 ** prob
    assert math.isclose(observed_probability, 1 / 512, rel_tol=3)
    print(f"ChaCha truncated differential: log2(prob) = {prob:.3f}, prob = {observed_probability:.6f}")


def test_differential_truncated_checker_salsa_permutation_input_fixed_and_output_truncated():
    """
    Test Crowley's truncated differential for 2 rounds [Cro2005]_.
    Crowley's "2 rounds" = 2 × (columnround + transpose)
    CLAASP: 2 half-rounds = 1 classical Salsa round (columnround OR rowround)
    CLAASP: 4 half-rounds = 2 classical rounds = 1 double-round (columnround + rowround)
    Crowley 2×R = 1 Salsa double-round = 4 CLAASP half-rounds
    """
    salsaPermutation = SalsaPermutation(number_of_rounds=4)
    input_trunc_diff = int("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 2)
    crowley_constraints = {
        (0, 1): 0x00201000,
        (0, 2): 0x40200000,
        (0, 3): 0x02000800,
        (2, 3): 0x00000040,
        (3, 0): 0x00000000,
        (3, 1): 0x00000100,
        (3, 2): 0x00200000,
        (3, 3): 0x04000080,
    }

    def build_truncated_pattern(constraints, state_bits):
        pattern = ['?'] * state_bits
        for (row, col), value in constraints.items():
            word_index = 4 * row + col
            start = 32 * word_index
            bits = f"{value:032b}"
            pattern[start:start + 32] = bits
        return ''.join(pattern)

    output_trunc_diff = build_truncated_pattern(crowley_constraints, 512)
    print(output_trunc_diff)
    
    number_of_samples = 1 << 12
    state_size = 512
    prob = differential_truncated_checker_permutation(
        salsaPermutation,
        input_trunc_diff, 
        output_trunc_diff,
        number_of_samples,
        state_size,
        seed=42,  # Use same seed as pattern generation
    )
    assert math.isfinite(prob)
    observed_probability = 2 ** prob
    assert math.isclose(observed_probability, 1 / 512, rel_tol=3)
    print(f"Salsa truncated differential (Crowley): log2(prob) = {prob:.3f}, prob = {observed_probability:.6f}")



def test_differential_truncated_checker_salsa_permutation_input_and_output_truncated():
    """
    Test Crowley's truncated differential for 2 rounds (starting from round 1) [Cro2005]_.
    Crowley's "2 rounds" = 2 × (columnround + transpose)
    CLAASP: 2 half-rounds = 1 classical Salsa round (columnround OR rowround)
    CLAASP: 4 half-rounds = 2 classical rounds = 1 double-round (columnround + rowround)
    Crowley 2×R = 1 Salsa double-round = 4 CLAASP half-rounds
    """
    salsaPermutation = SalsaPermutation(number_of_rounds=2, start_round=("even", "top"))
    input_trunc_diff = "0000000000000000000000000000000000000000001000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000????????????????????????????????00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000"
    crowley_constraints = {
        (0, 1): 0x00201000,
        (0, 2): 0x40200000,
        (0, 3): 0x02000800,
        (2, 3): 0x00000040,
        (3, 0): 0x00000000,
        (3, 1): 0x00000100,
        (3, 2): 0x00200000,
        (3, 3): 0x04000080,
    }

    def build_truncated_pattern(constraints, state_bits):
        pattern = ['?'] * state_bits
        for (row, col), value in constraints.items():
            word_index = 4 * row + col
            start = 32 * word_index
            bits = f"{value:032b}"
            pattern[start:start + 32] = bits
        return ''.join(pattern)

    output_trunc_diff = build_truncated_pattern(crowley_constraints, 512)
    print(output_trunc_diff)
    
    number_of_samples = 1 << 12
    state_size = 512
    prob = differential_truncated_checker_permutation_input_and_output_truncated(
        salsaPermutation,
        input_trunc_diff, 
        output_trunc_diff,
        number_of_samples,
        state_size,
        seed=43,  # Use same seed as pattern generation
    )
    assert math.isfinite(prob)
    observed_probability = 2 ** prob
    assert math.isclose(observed_probability, 1 / 512, rel_tol=3)
    print(f"Salsa truncated differential (Crowley): log2(prob) = {prob:.3f}, prob = {observed_probability:.6f}")


def test_differential_truncated_checker_salsa_permutation_input_and_output_truncated_2_rounds():
    """
    Test Crowley's truncated differential for 2 rounds (starting from round 1) [Cro2005]_.
    Crowley's "2 rounds" = 2 × (columnround + transpose)
    CLAASP: 2 half-rounds = 1 classical Salsa round (columnround OR rowround)
    CLAASP: 4 half-rounds = 2 classical rounds = 1 double-round (columnround + rowround)
    Crowley 2×R = 1 Salsa double-round = 4 CLAASP half-rounds
    """
    salsaPermutation = SalsaPermutation(number_of_rounds=4, start_round=("even", "top"))
    input_trunc_diff = "0000000000000000000000000000000000000000001000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000????????????????????????????????00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000"
    crowley_constraints = {
        (0, 3): 0x02002802,
    }

    def build_truncated_pattern(constraints, state_bits):
        pattern = ['?'] * state_bits
        for (row, col), value in constraints.items():
            word_index = 4 * row + col
            start = 32 * word_index
            bits = f"{value:032b}"
            pattern[start:start + 32] = bits
        return ''.join(pattern)

    output_trunc_diff = build_truncated_pattern(crowley_constraints, 512)
    number_of_samples = 1 << 15
    state_size = 512
    prob = differential_truncated_checker_permutation_input_and_output_truncated(
        salsaPermutation,
        input_trunc_diff, 
        output_trunc_diff,
        number_of_samples,
        state_size,
        seed=43,
    )
    assert math.isfinite(prob)
    observed_probability = 2 ** prob
    assert math.isclose(observed_probability, 1 / 512, rel_tol=3)
    print(f"Salsa truncated differential (Crowley): log2(prob) = {prob:.3f}, prob = {observed_probability:.6f}")

def test_truncated_differential_linear_checker_permutation():
    """
    Test the following forward differential-truncated-linear distinguishers.

    Distinguisher 1: 2 half rounds of ChaCha (1 classical round). Theoretical correlation is 0.

    10120220200000000101122222211010111011222110222022112200000000000000000000000000000000000000000010000000000000000000000000000000
    10120220220000000001002222211012111012222110222122121200000000001000000000000000000000000000000010000000000000000000000000000000
    12110211121122222222221111110002111112210222111122121221111111001022122200000000000000000000000010222222202000000000000000000000
    11122111111111201111022222112122111112221111111211111121122211111000000000000000022202221000000000000000000000001122222222200000

    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000010000000
    00000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000

    Distinguisher 2: 6 half rounds of ChaCha (3 classical rounds). Theoretical correlation is semi_deterministic cost: 1.01 and linear part cost: 3.
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000002100000

    00000001000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
    00000000000000001000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000
    00000000000000000000000100000000000000000000000000000000000000000000000000001000000000001100000000000000000000000000000000000001
    00000000000000000000000000000001000000000000000000000000000000000000000000000000000000001000000000000000000000000000000100000001
    """
    chacha = ChachaPermutation(number_of_rounds=4, round_mode=ROUND_MODE_HALF)
    input_truncated_diff = "".join((
        f"00000000000000000000000000000000011110222220222022200000222222111000000000000000000000000000000002221100222222220222200121000000",
        f"00000000000000000000000000000000000001222020022122200000222222100000000000000000000000000000000002221101222222220222200121000000",
        f"10000202221200000022211100000022020222202002212221222200222022221000000000000000000000000000000011120002222222200000220220111002",
        f"00122111222222220112121222020000111110110000000002122221110110121000000000000000100000000000000011111102211100001111001202222220"
    ))
    output_mask = "".join((
        f"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        f"00000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000",
        f"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000001",
        f"00000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ))

    correlation = truncated_differential_linear_checker_permutation(
        chacha,        
        input_truncated_diff,
        output_mask,
        number_of_samples=1 << 12,
        state_size=512,
        seed=43,
    )
    assert math.isfinite(correlation)
    assert 1 == abs(correlation)  # Theoretical correlation is 1
    print(f"Chacha truncated linear differential: correlation = {correlation:.6f}")

    chacha = ChachaPermutation(number_of_rounds=6, round_mode=ROUND_MODE_HALF)
    theoretical_correlation = 2 ** (-1.01 - 2*3)  # semi_deterministic cost + linear part cost
    input_truncated_diff = "".join((
        f"00000000000000000000000000000000011111111111111111111111111021100000000000000000000000000000000011201210000000111111110000000000",
        f"00000000000000000000000000000000111111111111111111111111111011100000000000000000000000000000000012111220000000111111210000000000",
        f"00210000000000000000000000000000200020011122221000000000000000000211111111000000000000000000000022200210001200021211120002000000",
        f"00000000000000002220000000000000011111111111111122222201211100100000000000000000000111111110000011011111000002201111122200122221"
    ))

    output_mask = "".join((
        f"00000001000000000000000100000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000",
        f"00000000000000001001000000000000000000000000100000000000100000000000000000000000000000000000000000000000000000000000000000000000",
        f"00000000000000000000000100100000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000",
        f"00000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
    ))

    correlation = truncated_differential_linear_checker_permutation(
        chacha,        
        input_truncated_diff,
        output_mask,
        number_of_samples=1 << 13,
        state_size=512,
        seed=42,
    )
    print(f"Chacha truncated linear differential: correlation = {correlation:.6f}")
    assert math.isfinite(correlation)
    assert math.isclose(abs(correlation), theoretical_correlation, rel_tol=0.5)


def test_linear_checker_for_block_cipher_single_key_zero_masks():
    speck = SpeckBlockCipher(number_of_rounds=4)
    block_size = speck.inputs_bit_size[0]
    key_size = speck.inputs_bit_size[1]

    correlation = linear_checker_for_block_cipher_single_key(
        speck,
        "0" * block_size,
        "0" * block_size,
        number_of_samples=1 << 10,
        block_size=block_size,
        key_size=key_size,
        fixed_key=0,
        seed=42,
    )

    assert correlation == 1
    
def test_differential_linear_continuous_checker_speck_block_cipher():
    """
    The expected values correspond to the continuous correlations of the
    differential-linear part reported in Table 4 from [BGGMP2023]_.
    """
    expected_cipher = [
        0.0, 0.5, 0.0, 0.984375, -0.96875, -0.9375, -0.875, -0.75,
        -0.5, -0.0, 1.0, -1.0, -1.0, -1.0, -1.0, -1.0,
        0.0, -0.5, 0.0, 0.984375, -0.96875, -0.9375, -0.875, -0.75,
        -0.5, -0.0, 1.0, -1.0, -1.0, -1.0, -1.0, 1.0
    ]
    expected_cipher_aligned = expected_cipher[::-1]

    speck_cipher = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=1)
    input_difference = 0x10005000

    number_of_samples = 1 << 17
    block_size = speck_cipher.inputs_bit_size[0]
    key_size = speck_cipher.inputs_bit_size[1]

    results = []
    fixed_key = 0x00000000
    seed = 29

    for bit_pos in range(32):
        msb_pos = block_size - 1 - bit_pos
        mask_str = ['x'] * block_size 
        mask_str[msb_pos] = '1'
        output_mask = ''.join(mask_str)

        experimental_corr = differential_linear_checker_for_block_cipher_single_key(
            speck_cipher,
            input_difference,
            output_mask,
            number_of_samples,
            block_size,
            key_size,
            fixed_key,
            seed
        )
        corr_adjusted = -experimental_corr
        results.append((bit_pos, corr_adjusted))

    print("\n" + "="*55)
    print(f"{'Bit Position':<8} | {'Experimental Corr.':<15} | {'Theoretical Corr.':<15}")
    print("="*55)

    tol_err = 0.05

    for bit, exp_corr in reversed(results):
        theo_corr = expected_cipher_aligned[bit]
        print(f"{bit:<8} | {exp_corr: .4f}        | {theo_corr: .4f}")
        assert math.isclose(exp_corr, theo_corr, abs_tol=tol_err)

    print("-" * 55 + "\n")
