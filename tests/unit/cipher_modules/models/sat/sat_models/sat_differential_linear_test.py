import itertools
import math

from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
from claasp.cipher_modules.models.sat.solvers import CADICAL_EXT
from claasp.cipher_modules.models.utils import (
    set_fixed_variables,
    integer_to_bit_list,
    differential_linear_checker_for_permutation,
    differential_linear_checker_for_block_cipher_single_key,
)
from claasp.ciphers.block_ciphers.aradi_block_cipher_sbox import AradiBlockCipherSBox
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation, ROUND_MODE_HALF
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY, SATISFIABLE


def test_differential_linear_trail_with_fixed_weight_6_rounds_speck():
    """Test for finding a differential-linear trail with fixed weight for 6 rounds of Speck."""
    speck = SpeckBlockCipher(number_of_rounds=6)
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2, 3):
        middle_part_components.append(speck.get_components_in_round(round_number))
    for round_number in range(3, 6):
        bottom_part_components.append(speck.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x05020402, 32, "big"),
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )

    ciphertext_difference = set_fixed_variables(
        component_id="cipher_output_5_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x00040004, 32, "big"),
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(speck, component_model_list)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=10, fixed_values=[key, plaintext, ciphertext_difference], solver_name=CADICAL_EXT, num_unknown_vars=2
    )
    assert trail["status"] == SATISFIABLE


def test_lowest_differential_linear_trail_with_fixed_weight_6_rounds_speck():
    """Test for finding the lowest differential-linear trail with fixed weight for 6 rounds of Speck."""
    speck = SpeckBlockCipher(number_of_rounds=6)
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2, 3):
        middle_part_components.append(speck.get_components_in_round(round_number))
    for round_number in range(3, 6):
        bottom_part_components.append(speck.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )

    ciphertext_difference = set_fixed_variables(
        component_id="cipher_output_5_12", constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(speck, component_model_list)

    trail = sat_heterogeneous_model.find_lowest_weight_xor_differential_linear_trail(
        fixed_values=[key, plaintext, ciphertext_difference], solver_name=CADICAL_EXT, num_unknown_vars=2
    )
    assert trail["status"] == SATISFIABLE


def test_differential_linear_trail_with_fixed_weight_3_rounds_chacha():
    """Test for finding a differential-linear trail with fixed weight for 3 rounds of ChaCha permutation."""
    chacha = ChachaPermutation(number_of_rounds=6, round_mode=ROUND_MODE_HALF)
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(1):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(1, 3):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(3, 6):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000,
            512,
            "big",
        ),
    )

    cipher_output_5_24 = set_fixed_variables(
        component_id="cipher_output_5_24",
        constraint_type="equal",
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x00010000000100010000000100030003000000800000008000000000000001800000000000000001000000010000000201000101010000000000010103000101,
            512,
            "big",
        ),
    )

    modadd_3_15 = set_fixed_variables(
        component_id=f"modadd_3_15", constraint_type="not_equal", bit_positions=range(32), bit_values=[0] * 32
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(chacha, component_model_list)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=5,
        fixed_values=[plaintext, modadd_3_15, cipher_output_5_24],
        solver_name=CADICAL_EXT,
        num_unknown_vars=511,
    )
    assert trail["status"] == SATISFIABLE
    assert trail["total_weight"] <= 5


def test_differential_linear_trail_with_fixed_weight_4_rounds_aradi():
    """Test for finding a differential-linear trail with fixed weight for 4 rounds of Aradi block cipher."""
    aradi = AradiBlockCipherSBox(number_of_rounds=4)
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(1):
        top_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(1, 3):
        middle_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(3, 4):
        bottom_part_components.append(aradi.get_components_in_round(round_number))
    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(128),
        bit_values=integer_to_bit_list(0x00000000000080000000000000008000, 128, "big"),
    )

    cipher_output_3_86 = set_fixed_variables(
        component_id="cipher_output_3_86",
        constraint_type="equal",
        bit_positions=range(128),
        bit_values=integer_to_bit_list(0x90900120800000011010002000000000, 128, "big"),
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(256), bit_values=[0] * 256
    )

    sbox_4_8 = set_fixed_variables(
        component_id="sbox_3_8", constraint_type="not_equal", bit_positions=range(4), bit_values=[0] * 4
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(aradi, component_model_list)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=10,
        fixed_values=[key, plaintext, sbox_4_8, cipher_output_3_86],
        solver_name=CADICAL_EXT,
        num_unknown_vars=128 - 1,
    )
    assert trail["status"] == SATISFIABLE
    assert trail["total_weight"] <= 10


def test_differential_linear_trail_with_fixed_weight_4_rounds_chacha():
    """Test for finding a differential-linear trail with fixed weight for 4 rounds of ChaCha permutation."""
    chacha = ChachaPermutation(number_of_rounds=8, round_mode=ROUND_MODE_HALF)
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(2, 4):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(4, 8):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000088088780,
            512,
            "big",
        ),
    )

    modadd_4_15 = set_fixed_variables(
        component_id="modadd_4_15", constraint_type="not_equal", bit_positions=range(32), bit_values=[0] * 32
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(chacha, component_model_list)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=32, fixed_values=[plaintext, modadd_4_15], solver_name=CADICAL_EXT, num_unknown_vars=511
    )
    assert trail["status"] == SATISFIABLE
    assert trail["total_weight"] <= 32


def test_differential_linear_trail_with_fixed_weight_4_rounds_chacha_second_case():
    """Test for finding a differential-linear trail with fixed weight for 4 rounds of ChaCha permutation."""
    chacha = ChachaPermutation(number_of_rounds=8, round_mode=ROUND_MODE_HALF)
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(2, 4):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(4, 8):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000088088780,
            512,
            "big",
        ),
    )

    modadd_4_15 = set_fixed_variables(
        component_id=f"modadd_4_15", constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(chacha, component_model_list)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=32, fixed_values=[plaintext, modadd_4_15], solver_name=CADICAL_EXT, num_unknown_vars=511
    )
    assert trail["status"] == SATISFIABLE
    assert trail["total_weight"] <= 32


def test_differential_linear_trail_with_fixed_weight_8_rounds_chacha_one_case():
    """Test for finding a differential-linear trail with fixed weight for 4 rounds of ChaCha permutation.
    This test is using in the middle part the semi-deterministic model.
    """
    chacha = ChachaPermutation(number_of_rounds=8, round_mode=ROUND_MODE_HALF)
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(2, 3):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(3, 8):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    state_size = 512
    initial_state_positions = [0] * state_size
    initial_state_positions[508] = 1

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(
            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000,
            state_size,
            "big",
        ),
    )

    intermediate_output_2_24_string = "0000000000000000000000000000000000000000000000000000000000000000001000000010000000000?10000000100000010000000000000000000000000000000000010000000000000000000000?100000000000100000000000000000000000100000000000100000000000100001000100010001000100010001000100000001000000010001000000010000000000000000000000000010000000000000000000000?1000000000001000000000000000100000001000000000001000000000000000000000000000000000000000?100000001000100000001000000000000000000000000001000000000000000000000011000000000001000000"
    intermediate_output_2_24_position_values = []
    for intermediate_output_2_24_char in intermediate_output_2_24_string:
        if intermediate_output_2_24_char == "?":
            intermediate_output_2_24_position_values.append(2)
        else:
            intermediate_output_2_24_position_values.append(int(intermediate_output_2_24_char))

    intermediate_output_2_24 = set_fixed_variables(
        component_id="intermediate_output_2_24",
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=intermediate_output_2_24_position_values,
    )

    ciphertext = set_fixed_variables(
        component_id="cipher_output_7_24",
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(
            0x00000001000000000000000101010181000080800000000000000000000800800000100000000101000000010000000000000000000000010100000100000101,
            state_size,
            "big",
        ),
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(
        chacha, component_model_list, middle_part_model="sat_semi_deterministic_truncated_xor_differential_constraints"
    )

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=60,
        fixed_values=[plaintext, ciphertext, intermediate_output_2_24],
        solver_name=CADICAL_EXT,
        num_unknown_vars=8,
        unknown_window_size_configuration={
            "max_number_of_sequences_window_size_0": 80,
            "max_number_of_sequences_window_size_1": 25,
            "max_number_of_sequences_window_size_2": 190,
        },
    )
    assert trail["status"] == SATISFIABLE
    assert trail["total_weight"] == 11


def test_differential_linear_trail_with_fixed_weight_4_rounds_chacha_golden():
    """Test for finding a differential-linear trail with fixed weight for 4 rounds of ChaCha permutation.
    This test is using in the middle part the semi-deterministic model.
    """
    chacha = ChachaPermutation(number_of_rounds=8, round_mode=ROUND_MODE_HALF)
    # import ipdb; ipdb.set_trace()
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(2, 4):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(4, 8):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    state_size = 512

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=list(range(state_size)),
        bit_values=(0,) * state_size,
    )

    modadd_3_0 = set_fixed_variables(
        component_id="modadd_4_0", constraint_type="not_equal", bit_positions=list(range(32)), bit_values=(0,) * 32
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(
        chacha, component_model_list, middle_part_model="sat_semi_deterministic_truncated_xor_differential_constraints"
    )

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=12,
        fixed_values=[plaintext, modadd_3_0],
        solver_name=CADICAL_EXT,
        num_unknown_vars=8,
    )
    assert trail["status"] == SATISFIABLE
    assert trail["total_weight"] <= 12


def test_diff_lin_chacha():
    """
    This test is verifying experimentally the test test_differential_linear_trail_with_fixed_weight_3_rounds_chacha
    """
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000
    output_mask = 0x00010000000100010000000100030003000000800000008000000000000001800000000000000001000000010000000201000101010000000000010103000101
    number_of_samples = 2**12
    number_of_rounds = 6
    state_size = 512
    chacha = ChachaPermutation(number_of_rounds=number_of_rounds, round_mode=ROUND_MODE_HALF)
    corr = differential_linear_checker_for_permutation(
        chacha, input_difference, output_mask, number_of_samples, state_size
    )
    abs_corr = abs(corr)
    assert abs(math.log(abs_corr, 2)) < 3


def test_diff_lin_chacha_8():
    """
    This test is verifying experimentally the test test_differential_linear_trail_with_fixed_weight_3_rounds_chacha
    """
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000
    output_mask = 0x00000001000000000000000101010181000080800000000000000000000800800000100000000101000000010000000000000000000000010100000100000101
    number_of_samples = 2**10
    number_of_rounds = 8
    state_size = 512
    chacha = ChachaPermutation(number_of_rounds=number_of_rounds, round_mode=ROUND_MODE_HALF)
    corr = differential_linear_checker_for_permutation(
        chacha, input_difference, output_mask, number_of_samples, state_size
    )
    abs_corr = abs(corr)
    assert abs(math.log(abs_corr, 2)) < 8


def test_diff_lin_speck():
    """
    This test is verifying experimentally the test test_differential_linear_trail_with_fixed_weight_6_rounds_speck
    """
    input_difference = 0x02110A04
    output_mask = 0x02000201
    number_of_samples = 2**15
    number_of_rounds = 6
    fixed_key = 0x0
    speck = SpeckBlockCipher(number_of_rounds=number_of_rounds)
    block_size = speck.inputs_bit_size[0]
    key_size = speck.inputs_bit_size[1]
    corr = differential_linear_checker_for_block_cipher_single_key(
        speck, input_difference, output_mask, number_of_samples, block_size, key_size, fixed_key, seed=42
    )
    abs_corr = abs(corr)
    assert abs(math.log(abs_corr, 2)) <= 8


def test_diff_lin_aradi():
    """
    This test is verifying experimentally the test test_differential_linear_trail_with_fixed_weight_4_rounds_aradi
    """
    input_difference = 0x00000000000080000000000000008000
    output_mask = 0x90900120800000011010002000000000
    number_of_samples = 2**12
    number_of_rounds = 4
    fixed_key = 0x90900120800000011010002000000000
    speck = AradiBlockCipherSBox(number_of_rounds=number_of_rounds)
    block_size = speck.inputs_bit_size[0]
    key_size = speck.inputs_bit_size[1]
    corr = differential_linear_checker_for_block_cipher_single_key(
        speck, input_difference, output_mask, number_of_samples, block_size, key_size, fixed_key, seed=42
    )
    abs_corr = abs(corr)
    assert abs(math.log(abs_corr, 2)) < 8
