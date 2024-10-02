import time

import numpy as np

from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.ciphers.block_ciphers.aradi_block_cipher_sbox import AradiBlockCipherSBox
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.ciphers.permutations.gaston_sbox_permutation import GastonSboxPermutation
from claasp.ciphers.permutations.gaston_sbox_permutation_top import GastonSboxPermutationTop
from claasp.utils.utils import get_k_th_bit


def generate_component_model_types(speck_cipher):
    """Generates the component model types for a given Speck cipher."""
    component_model_types = []
    for component in speck_cipher.get_all_components():
        component_model_types.append({
            "component_id": component.id,
            "component_object": component,
            "model_type": "sat_xor_differential_propagation_constraints"
        })
    return component_model_types


def update_component_model_types_for_truncated_components(component_model_types, truncated_components):
    """Updates the component model types for truncated components."""
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in truncated_components:
            component_model_type["model_type"] = "sat_bitwise_deterministic_truncated_xor_differential_constraints"


def update_component_model_types_for_linear_components(component_model_types, linear_components):
    """Updates the component model types for linear components."""
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in linear_components:
            component_model_type["model_type"] = "sat_xor_linear_mask_propagation_constraints"


def extract_bits(columns, positions):
    num_positions = len(positions)
    num_columns = columns.shape[1]
    bit_size = columns.shape[0] * 8
    # Initialize the result array
    result = np.zeros((num_positions, num_columns), dtype=np.uint8)

    # Loop to fill the result array with the required bits
    for i in range(num_positions):
        for j in range(num_columns):
            byte_index = (bit_size - positions[i] -1) // 8
            bit_index = positions[i] % 8
            result[i, j] = get_k_th_bit(columns[:, j][byte_index], bit_index)
    return result
def number_to_n_bit_binary_string(number, n_bits):
    """Converts a number to an n-bit binary string with leading zero padding."""
    return format(number, f'0{n_bits}b')

def extract_bit_positions1(binary_str):
    """Extracts bit positions from a binary+unknows string."""
    binary_str = binary_str[::-1]

    positions = [i for i, bit in enumerate(binary_str) if bit in ['1']]
    return positions

def extract_bit_positions(hex_number):
    binary_str = number_to_n_bit_binary_string(hex_number, 512)
    print(len(binary_str), binary_str)
    #binary_str = bin(hex_number)[2:]  # bin() converts to binary, [2:] strips the '0b' prefix

    # Reverse the binary string to make the least significant bit at index 0
    binary_str = binary_str[::-1]

    # Find positions of '1's
    positions = [i for i, bit in enumerate(binary_str) if bit == '1']

    return positions


def repeat_input_difference(input_difference, num_samples, num_bytes):
    """Repeats the input difference to generate a large sample for testing."""
    bytes_array = input_difference.to_bytes(num_bytes, 'big')
    np_array = np.array(list(bytes_array), dtype=np.uint8)
    column_array = np_array.reshape(-1, 1)
    return np.tile(column_array, (1, num_samples))


def test_differential_linear_trail_with_fixed_weight_3_rounds_speck():
    """Test for finding a differential-linear trail with fixed weight for 8 rounds of Speck."""
    aradi = SpeckBlockCipher(number_of_rounds=5)
    import itertools

    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(2, 4):
        middle_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(4, 5):
        bottom_part_components.append(aradi.get_components_in_round(round_number))
    top_part_components = list(itertools.chain(*top_part_components))
    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32
    )

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64
    )

    modadd_2_7 = set_fixed_variables(
        component_id='modadd_4_7',
        constraint_type='not_equal',
        bit_positions=range(4),
        bit_values=[0] * 4
    )

    component_model_types = generate_component_model_types(aradi)
    update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(aradi, component_model_types)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=4, fixed_values=[key, plaintext, modadd_2_7], solver_name="CADICAL_EXT", num_unknown_vars=31
    )
    print(trail)
    assert trail["status"] == 'SATISFIABLE'

def test_differential_linear_trail_with_fixed_weight_3_rounds_ascon():
    """Test for finding a differential-linear trail with fixed weight for 8 rounds of Speck."""
    aradi = GastonSboxPermutationTop(number_of_rounds=3)
    import itertools

    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(1):
        top_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(1, 2):
        middle_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(2, 3):
        bottom_part_components.append(aradi.get_components_in_round(round_number))
    top_part_components = list(itertools.chain(*top_part_components))
    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(640),
        bit_values=[0] * 640
    )


    modadd_2_7 = set_fixed_variables(
        component_id='sbox_2_88',
        constraint_type='not_equal',
        bit_positions=range(5),
        bit_values=[0] * 5
    )

    component_model_types = generate_component_model_types(aradi)
    update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(aradi, component_model_types)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=4, fixed_values=[plaintext, modadd_2_7], solver_name="CADICAL_EXT", num_unknown_vars=639
    )
    print(trail)
    assert trail["status"] == 'SATISFIABLE'


def generate_uint32_array_from_hex(prefix, hex_string):
    # Ensure the hex string is exactly 512 bits (128 hex characters)
    if len(hex_string) < 128:
        hex_string = hex_string.zfill(128)  # Pad with leading zeros if necessary

    # Split the hex string into 32-bit chunks (8 hex characters each)
    chunks = [hex_string[i:i + 8] for i in range(0, len(hex_string), 8)]

    # Convert each chunk to a 32-bit integer with '0x' format for C-like output
    formatted_chunks = ["0x" + chunk.upper() for chunk in chunks]

    # Construct the C-style uint32_t array as a string
    uint32_array = f"uint32_t {prefix}[16] = {{ " + ", ".join(formatted_chunks) + " };"

    return uint32_array

def test_differential_linear_trail_with_fixed_weight_3_rounds_chacha():
    """Test for finding a differential-linear trail with fixed weight for 8 rounds of Speck."""
    nr = 8
    aradi = ChachaPermutation(number_of_rounds=nr)

    #aradi.print()
    import itertools

    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(3):
        top_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(3, 5):
        middle_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(5, 8):
        bottom_part_components.append(aradi.get_components_in_round(round_number))
    top_part_components = list(itertools.chain(*top_part_components))
    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext1 = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(512),
        bit_values=[0] * 512
    )

    plaintext2 = set_fixed_variables(
        component_id='plaintext',
        constraint_type='equal',
        bit_positions=range(384),
        bit_values=[0] * 384
    )


    modadd_2_7 = set_fixed_variables(
        component_id=f'modadd_5_15',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32
    )

    #modadd_2_7 = set_fixed_variables(
    #    component_id=f'f"cipher_output_{nr-1}_24"',
    #    constraint_type='not_equal',
    #    bit_positions=range(512),
    #    bit_values=[0] * 512
    #)

    component_model_types = generate_component_model_types(aradi)
    update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(aradi, component_model_types)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=90, fixed_values=[plaintext1, plaintext2, modadd_2_7], solver_name="CADICAL_EXT", num_unknown_vars=511
    )
    print(trail)
    print(generate_uint32_array_from_hex("ID", trail["components_values"]["plaintext"]["value"]))
    print(generate_uint32_array_from_hex("ODmask", trail["components_values"][f"cipher_output_{nr-1}_24"]["value"]))
    assert trail["status"] == 'SATISFIABLE'


def test_diff_lin_gaston():
    """
    # input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000001
    # output_mask = 0x00000000000000000000000000000000000000000000000000000100000000000000002000000000
    """

    input_difference = 0x0020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    output_mask =      0x0000000000000040000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

    number_of_samples = 2 ** 12
    start_building_time = time.time()
    rng = np.random.default_rng()
    input_difference_data = repeat_input_difference(input_difference, number_of_samples, 80)
    end_building_time = time.time()
    sat_time = end_building_time - start_building_time
    print("Time in seconds", sat_time)
    nr = 3
    gaston = GastonSboxPermutationTop(number_of_rounds=nr)
    plaintext1 = rng.integers(low=0, high=256, size=(80, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data
    start_building_time = time.time()
    ciphertext1 = gaston.evaluate_vectorized([plaintext1])
    sat_time = end_building_time - start_building_time
    print("Time in seconds", sat_time)
    ciphertext2 = gaston.evaluate_vectorized([plaintext2])
    ciphertext3 = ciphertext1[0] ^ ciphertext2[0]
    bit_positions_ciphertext = extract_bit_positions(output_mask)
    ccc = extract_bits(ciphertext3.T, bit_positions_ciphertext)
    print(ccc)
    count = 0
    for i in range(number_of_samples):
        c_xor = np.bitwise_xor.reduce(ccc.T[i])
        if c_xor == 0:
            count += 1
    corr = 2*count/number_of_samples*1.0-1
    import math
    print("Correlation:", corr, "Exponent of 2", math.log(abs(corr), 2))


def test_diff_lin_chacha():
    """
    # input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000001
    # output_mask = 0x00000000000000000000000000000000000000000000000000000100000000000000002000000000
    """

    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080088008
    output_mask =      0x00010001000000010000000000000000000000000000008000000000000000000000000000000000000000010000000100000101000000000000000001000000

    number_of_samples = 2 ** 21
    start_building_time = time.time()
    rng = np.random.default_rng()
    input_difference_data = repeat_input_difference(input_difference, number_of_samples, 64)
    end_building_time = time.time()
    sat_time = end_building_time - start_building_time
    print("Time in seconds", sat_time)
    nr = 8
    gaston = ChachaPermutation(number_of_rounds=nr)
    plaintext1 = rng.integers(low=0, high=256, size=(64, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data
    start_building_time = time.time()
    ciphertext1 = gaston.evaluate_vectorized([plaintext1])
    sat_time = end_building_time - start_building_time
    print("Time in seconds", sat_time)
    ciphertext2 = gaston.evaluate_vectorized([plaintext2])
    ciphertext3 = ciphertext1[0] ^ ciphertext2[0]
    bit_positions_ciphertext = extract_bit_positions(output_mask)
    ccc = extract_bits(ciphertext3.T, bit_positions_ciphertext)
    print(ccc)
    count = 0
    for i in range(number_of_samples):
        c_xor = np.bitwise_xor.reduce(ccc.T[i])
        if c_xor == 0:
            count += 1
    corr = 2*count/number_of_samples*1.0-1
    import math
    print("Correlation:", corr, "Exponent of 2", math.log(abs(corr), 2))