import numpy as np
from claasp.cipher_modules.models.sat.sat_models.sat_regular_and_deterministic_xor_truncated_differential import (
    SatRegularAndDeterministicXorTruncatedDifferential
)
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.utils.utils import get_k_th_bit

WORD_SIZE = 16
MASK_VAL = 2 ** WORD_SIZE - 1
ALPHA = 7
BETA = 2


def speck_rol(value, shift):
    """Performs a left rotation on a 16-bit word."""
    return ((value << shift) & MASK_VAL) | (value >> (WORD_SIZE - shift))


def speck_ror(value, shift):
    """Performs a right rotation on a 16-bit word."""
    return (value >> shift) | ((value << (WORD_SIZE - shift)) & MASK_VAL)


def speck_encrypt_round(plaintext, subkey):
    """Performs one round of encryption for Speck32/64."""
    left_part, right_part = plaintext
    left_part = speck_ror(left_part, ALPHA)
    left_part = (left_part + right_part) & MASK_VAL
    left_part ^= subkey
    right_part = speck_rol(right_part, BETA)
    right_part ^= left_part
    return left_part, right_part


def speck_decrypt_round(ciphertext, subkey):
    """Performs one round of decryption for Speck32/64."""
    left_part, right_part = ciphertext
    right_part ^= left_part
    right_part = speck_ror(right_part, BETA)
    left_part ^= subkey
    left_part = (left_part - right_part) & MASK_VAL
    left_part = speck_rol(left_part, ALPHA)
    return left_part, right_part


def speck_encrypt(plaintext, subkeys):
    """Encrypts the given plaintext using the provided subkeys."""
    left_part, right_part = plaintext
    for subkey in subkeys:
        left_part, right_part = speck_encrypt_round((left_part, right_part), subkey)
    return left_part, right_part


def speck_decrypt(ciphertext, subkeys):
    """Decrypts the given ciphertext using the provided key schedule."""
    left_part, right_part = ciphertext
    for subkey in reversed(subkeys):
        left_part, right_part = speck_decrypt_round((left_part, right_part), subkey)
    return left_part, right_part


def speck_key_expansion(key, rounds):
    """Expands a key for the specified number of rounds of encryption."""
    ks = [0] * rounds
    ks[0] = key[-1]
    left_words = list(reversed(key[:-1]))
    for i in range(rounds - 1):
        left_words[i % len(left_words)], ks[i + 1] = speck_encrypt_round((left_words[i % len(left_words)], ks[i]), i)
    return ks


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


def extract_bits(columns, positions):
    """Extracts the bits from columns at the specified positions."""
    num_positions = len(positions)
    num_columns = columns.shape[1]
    bit_size = columns.shape[0] * 8

    result = np.zeros((num_positions, num_columns), dtype=np.uint8)

    for i in range(num_positions):
        for j in range(num_columns):
            byte_index = (bit_size - positions[i] - 1) // 8
            bit_index = positions[i] % 8
            result[i, j] = get_k_th_bit(columns[:, j][byte_index], bit_index)
    return result


def extract_bit_positions(binary_str):
    """Extracts bit positions from a binary+unknows string."""
    binary_str = binary_str[::-1]
    positions = [i for i, bit in enumerate(binary_str) if bit in ['1', '0']]
    return positions


def repeat_input_difference(input_difference, num_samples, num_bytes):
    """Repeats the input difference to generate a large sample for testing."""
    bytes_array = input_difference.to_bytes(num_bytes, 'big')
    np_array = np.array(list(bytes_array), dtype=np.uint8)
    column_array = np_array.reshape(-1, 1)
    return np.tile(column_array, (1, num_samples))


def test_differential_in_single_key_scenario_speck3264():
    """
    This test is checking the resulting probability after combining two differentials, one regular and one truncated.
    The regular one occurs with probability 2^-12 and the truncated one occurs with probability 1. The regular differential
    start with a fixed input difference of 0xfe2ecdf8 and the output difference is 007ce000. The truncated differential
    starts with a fixed input difference of 007ce000 and the output difference is ????100000000000????100000000011. The
    expected probability for the resulting differential is approximately 2^-12.
    """
    speck = SpeckBlockCipher(number_of_rounds=3)
    rng = np.random.default_rng(seed=42)
    num_samples = 2 ** 14
    input_diff = 0xfe2ecdf8
    output_diff = "????100000000000????100000000011"

    # Generate input data
    input_diff_data = repeat_input_difference(input_diff, num_samples, 4)
    key_data = rng.integers(low=0, high=256, size=(8, num_samples), dtype=np.uint8)
    plaintext_data1 = rng.integers(low=0, high=256, size=(4, num_samples), dtype=np.uint8)
    plaintext_data2 = plaintext_data1 ^ input_diff_data

    # Encrypt and evaluate
    ciphertext1 = speck.evaluate_vectorized([plaintext_data1, key_data])
    ciphertext2 = speck.evaluate_vectorized([plaintext_data2, key_data])
    diff_ciphertext = ciphertext1[0] ^ ciphertext2[0]

    # Check bit positions
    bit_positions = extract_bit_positions(output_diff)
    known_bits = extract_bits(diff_ciphertext.T, bit_positions)
    inv_output_diff = output_diff[::-1]

    filled_bits = [int(bit) for bit in inv_output_diff if bit in ["0", "1"]]

    # Calculate probability
    total = 0
    for i in range(len(known_bits[0])):
        if np.all(known_bits[:, i] == filled_bits):
            total += 1

    import math
    prob_weight = math.log(total / num_samples, 2)
    assert 14 > abs(prob_weight) > 11


def test_find_one_xor_regular_truncated_differential_trail_with_fixed_weight_4_rounds():
    """Test for finding a XOR regular truncated differential trail with fixed weight for 4 rounds."""
    speck = SpeckBlockCipher(number_of_rounds=4)

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id='intermediate_output_1_12',
        constraint_type='equal',
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64
    )

    component_model_types = generate_component_model_types(speck)
    truncated_components = [
        'constant_2_0',
        'rot_2_1',
        'modadd_2_2',
        'xor_2_3',
        'rot_2_4',
        'xor_2_5',
        'rot_2_6',
        'modadd_2_7',
        'xor_2_8',
        'rot_2_9',
        'xor_2_10',
        'intermediate_output_2_11',
        'intermediate_output_2_12',
        'constant_3_0',
        'rot_3_1',
        'modadd_3_2',
        'xor_3_3',
        'rot_3_4',
        'xor_3_5',
        'rot_3_6',
        'modadd_3_7',
        'xor_3_8',
        'rot_3_9',
        'xor_3_10',
        'intermediate_output_3_11',
        'intermediate_output_3_12',
        'cipher_output_3_12'
    ]
    update_component_model_types_for_truncated_components(component_model_types, truncated_components)

    sat_heterogeneous_model = SatRegularAndDeterministicXorTruncatedDifferential(speck, component_model_types)
    trail = sat_heterogeneous_model.find_one_xor_regular_truncated_differential_trail_with_fixed_weight(
        weight=8, fixed_values=[intermediate_output_1_12, key, plaintext], solver_name="CRYPTOMINISAT_EXT"
    )

    assert trail['components_values']['cipher_output_3_12']['value'] == '????????00000000????????000000?1'


def test_find_one_xor_regular_truncated_differential_trail_with_fixed_weight_5_rounds():
    """Test for finding a XOR regular truncated differential trail with fixed weight for 5 rounds."""
    speck = SpeckBlockCipher(number_of_rounds=5)

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id='intermediate_output_1_12',
        constraint_type='equal',
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64
    )

    component_model_types = generate_component_model_types(speck)
    truncated_components = [
        'constant_2_0', 'rot_2_1', 'modadd_2_2', 'xor_2_3', 'rot_2_4',
        'xor_2_5', 'rot_2_6', 'modadd_2_7', 'xor_2_8', 'rot_2_9', 'xor_2_10',
        'intermediate_output_2_11', 'intermediate_output_2_12',
        'constant_3_0', 'rot_3_1', 'modadd_3_2', 'xor_3_3', 'rot_3_4',
        'xor_3_5', 'rot_3_6', 'modadd_3_7', 'xor_3_8', 'rot_3_9', 'xor_3_10',
        'intermediate_output_3_11', 'intermediate_output_3_12',
        'constant_4_0', 'rot_4_1', 'modadd_4_2', 'xor_4_3', 'rot_4_4',
        'xor_4_5', 'rot_4_6', 'modadd_4_7', 'xor_4_8', 'rot_4_9', 'xor_4_10',
        'intermediate_output_4_11', 'intermediate_output_4_12', 'cipher_output_4_12'
    ]
    update_component_model_types_for_truncated_components(component_model_types, truncated_components)

    sat_heterogeneous_model = SatRegularAndDeterministicXorTruncatedDifferential(speck, component_model_types)
    trail = sat_heterogeneous_model.find_one_xor_regular_truncated_differential_trail_with_fixed_weight(
        weight=8, fixed_values=[intermediate_output_1_12, key, plaintext], solver_name="CRYPTOMINISAT_EXT"
    )

    assert trail['components_values']['cipher_output_4_12']['value'] == '???????????????0????????????????'

def test_wrong_fixed_variables_assignment():
    speck = SpeckBlockCipher(number_of_rounds=5)

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64
    )

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id='intermediate_output_1_12',
        constraint_type='equal',
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )

    modadd_1_2 = set_fixed_variables(
        component_id='modadd_1_2',
        constraint_type='equal',
        bit_positions=range(32),
        bit_values=(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )
    )
    component_model_types = generate_component_model_types(speck)
    sat_bitwise_deterministic_truncated_components = [
        'constant_2_0',
        'rot_2_1',
        'modadd_2_2',
        'xor_2_3',
        'rot_2_4',
        'xor_2_5',
        'rot_2_6',
        'modadd_2_7',
        'xor_2_8',
        'rot_2_9',
        'xor_2_10',
        'intermediate_output_2_11',
        'intermediate_output_2_12',
        'constant_3_0',
        'rot_3_1',
        'modadd_3_2',
        'xor_3_3',
        'rot_3_4',
        'xor_3_5',
        'rot_3_6',
        'modadd_3_7',
        'xor_3_8',
        'rot_3_9',
        'xor_3_10',
        'intermediate_output_3_11',
        'intermediate_output_3_12',
        'constant_4_0',
        'rot_4_1',
        'modadd_4_2',
        'xor_4_3',
        'rot_4_4',
        'xor_4_5',
        'rot_4_6',
        'modadd_4_7',
        'xor_4_8',
        'rot_4_9',
        'xor_4_10',
        'intermediate_output_4_11',
        'intermediate_output_4_12',
        'cipher_output_4_12'
    ]
    update_component_model_types_for_truncated_components(
        component_model_types, sat_bitwise_deterministic_truncated_components
    )

    sat_heterogeneous_model = SatRegularAndDeterministicXorTruncatedDifferential(speck, component_model_types)

    import pytest
    with pytest.raises(ValueError) as exc_info:
        sat_heterogeneous_model.find_one_xor_regular_truncated_differential_trail_with_fixed_weight(
            8,
            31,
            [intermediate_output_1_12, key, plaintext, modadd_1_2],
            "CRYPTOMINISAT_EXT"
        )
        assert str(exc_info.value) == "The fixed value in a regular XOR differential model cannot be 2"
