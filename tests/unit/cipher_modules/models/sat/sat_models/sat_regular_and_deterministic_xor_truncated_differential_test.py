import numpy as np
from claasp.cipher_modules.models.sat.sat_models.sat_regular_and_deterministic_xor_truncated_differential import \
    SatRegularAndDeterministicXorTruncatedDifferential
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.utils.utils import get_k_th_bit


def speck32_64_word_size():
    return 16


def speck32_64_alpha():
    return 7


def speck32_64_beta():
    return 2


MASK_VAL = 2 ** speck32_64_word_size() - 1


def speck32_64_rol(x, k):
    return ((x << k) & MASK_VAL) | (x >> (speck32_64_word_size() - k))


def speck32_64_ror(x, k):
    return (x >> k) | ((x << (speck32_64_word_size() - k)) & MASK_VAL)


def speck32_64_decrypt(ciphertext, ks):
    def dec_one_round(c, subkey_):
        c0, c1 = c
        c1 = c1 ^ c0
        c1 = speck32_64_ror(c1, speck32_64_beta())
        c0 = c0 ^ subkey_
        c0 = (c0 - c1) & MASK_VAL
        c0 = speck32_64_rol(c0, speck32_64_alpha())
        return c0, c1
    x, y = ciphertext
    for subkey in reversed(ks):
        x, y = dec_one_round((x, y), subkey)
    return x, y


def speck32_64_enc_one_round(plaintext, subkey):
    c0, c1 = plaintext
    c0 = speck32_64_ror(c0, speck32_64_alpha())
    c0 = (c0 + c1) & MASK_VAL
    c0 = c0 ^ subkey
    c1 = speck32_64_rol(c1, speck32_64_beta())
    c1 = c1 ^ c0
    return c0, c1


def speck32_64_expand_key(k, t):
    ks = [0] * t
    ks[0] = k[-1]
    left_word = list(reversed(k[:-1]))
    for i in range(t - 1):
        left_word[i % len(left_word)], ks[i + 1] = speck32_64_enc_one_round((left_word[i % len(left_word)], ks[i]), i)
    return ks


def speck32_64_encrypt(p, ks):

    x, y = p
    for k in ks:
        x, y = speck32_64_enc_one_round((x, y), k)
    return x, y


def test_find_one_xor_regular_truncated_differential_trail_with_fixed_weight():
    component_model_types = []
    speck = SpeckBlockCipher(number_of_rounds=3)
    for component in speck.get_all_components():
        component_model_type = {
            "component_id": component.id,
            "component_object": component,
            "model_type": "sat_xor_differential_propagation_constraints"
        }
        component_model_types.append(component_model_type)

    sat_bitwise_deterministic_truncated_components = [
        'xor_2_10', 'rot_2_9', 'xor_2_8', 'modadd_2_7', 'rot_2_6', 'xor_2_5', 'rot_2_4', 'xor_2_3',
        'modadd_2_2', 'rot_2_1', 'constant_2_0', 'cipher_output_2_12', 'intermediate_output_2_11'
    ]
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in sat_bitwise_deterministic_truncated_components:
            component_model_type["model_type"] = "sat_bitwise_deterministic_truncated_xor_differential_constraints"

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32)
    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64)

    sat_heterogeneous_model = SatRegularAndDeterministicXorTruncatedDifferential(speck, component_model_types)
    result = sat_heterogeneous_model.find_one_xor_regular_truncated_differential_trail_with_fixed_weight(
        2, 32, [plaintext, key], "CRYPTOMINISAT_EXT"
    )
    assert result["status"] == "SATISFIABLE"


def extract_bits(columns, positions):
    num_positions = len(positions)
    num_columns = columns.shape[1]
    bit_size = columns.shape[0] * 8

    result = np.zeros((num_positions, num_columns), dtype=np.uint8)

    # Loop to fill the result array with the required bits
    for i in range(num_positions):
        for j in range(num_columns):
            byte_index = (bit_size - positions[i] -1) // 8
            bit_index = positions[i] % 8
            result[i, j] = get_k_th_bit(columns[:, j][byte_index], bit_index)
    return result


def extract_bit_positions(binary_str):
    binary_str = binary_str[::-1]
    positions = [i for i, bit in enumerate(binary_str) if bit == '1' or bit == '0']

    return positions


def repeat_input_difference(input_difference_, number_of_samples_, number_of_bytes_):
    bytes_array = input_difference_.to_bytes(number_of_bytes_, 'big')
    np_array = np.array(list(bytes_array), dtype=np.uint8)
    column_array = np_array.reshape(-1, 1)
    return np.tile(column_array, (1, number_of_samples_))


def test_differential_in_single_key_scenario_speck3264():
    """
    This test is checking the resulting probability after combining two differential, one regular and one truncated.
    The regular one occurs with probability 2^-12 and the truncated one occurs with probability 1. The regular differential
    start with a fixed input difference of 0xfe2ecdf8 and the output difference is 007ce000. The truncated differential
    starts with a fixed input difference of 007ce000 and the output difference is ????100000000000????100000000011. The
    expected probability for the resulting differential is approximately 2^-12.
    """
    speck = SpeckBlockCipher(number_of_rounds=3)
    rng = np.random.default_rng(seed=42)
    number_of_samples = 2**14
    input_difference = 0xfe2ecdf8
    output_difference = "????100000000000????100000000011"
    input_difference_data = repeat_input_difference(input_difference, number_of_samples, 4)
    key_data = rng.integers(low=0, high=256, size=(8, number_of_samples), dtype=np.uint8)
    plaintext_data1 = rng.integers(low=0, high=256, size=(4, number_of_samples), dtype=np.uint8)
    plaintext_data2 = plaintext_data1 ^ input_difference_data
    ciphertext1 = speck.evaluate_vectorized([plaintext_data1, key_data])
    ciphertext2 = speck.evaluate_vectorized([plaintext_data2, key_data])
    ciphertext3 = ciphertext1[0] ^ ciphertext2[0]
    bit_positions_ciphertext = extract_bit_positions(output_difference)
    known_bit_positions = extract_bits(ciphertext3.T, bit_positions_ciphertext)
    inv_output_difference = output_difference[::-1]

    inv_output_difference_only_filled = [int(symbol) for symbol in inv_output_difference if symbol in ["0", "1"]]
    total = 0
    for idx in range(len(known_bit_positions[0])):
        if (np.all(known_bit_positions[:, idx] == inv_output_difference_only_filled)):
            total += 1
    import math
    total_prob_weight = math.log(total/number_of_samples, 2)
    assert 14 > abs(total_prob_weight) > 11


def test_find_one_xor_regular_truncated_differential_trail_with_fixed_weight_4_rounds():
    component_model_types = []
    speck = SpeckBlockCipher(number_of_rounds=4)

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32)
    intermediate_output_1_12 = set_fixed_variables(component_id='intermediate_output_1_12', constraint_type='equal',
                                                   bit_positions=range(32),
                                                   bit_values=(
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64)
    for component in speck.get_all_components():
        component_model_type = {
            "component_id": component.id,
            "component_object": component,
            "model_type": "sat_xor_differential_propagation_constraints"
        }
        component_model_types.append(component_model_type)
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
        'cipher_output_3_12'
    ]
    # sat_bitwise_deterministic_truncated_components = []
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in sat_bitwise_deterministic_truncated_components:
            component_model_type["model_type"] = "sat_bitwise_deterministic_truncated_xor_differential_constraints"
    sat_heterogeneous_model = SatRegularAndDeterministicXorTruncatedDifferential(speck, component_model_types)
    trail = sat_heterogeneous_model.find_one_xor_regular_truncated_differential_trail_with_fixed_weight(
        8,
        31,
        [intermediate_output_1_12, key, plaintext],
        "CRYPTOMINISAT_EXT"
    )
    assert trail['components_values']['cipher_output_3_12']['value'] == '????????00000000????????000000?1'


def test_find_one_xor_regular_truncated_differential_trail_with_fixed_weight_5_rounds():
    component_model_types = []
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

    for component in speck.get_all_components():
        component_model_type = {
            "component_id": component.id,
            "component_object": component,
            "model_type": "sat_xor_differential_propagation_constraints"
        }
        component_model_types.append(component_model_type)

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
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in sat_bitwise_deterministic_truncated_components:
            component_model_type["model_type"] = "sat_bitwise_deterministic_truncated_xor_differential_constraints"

    sat_heterogeneous_model = SatRegularAndDeterministicXorTruncatedDifferential(speck, component_model_types)
    trail = sat_heterogeneous_model.find_one_xor_regular_truncated_differential_trail_with_fixed_weight(
            8, 31, [intermediate_output_1_12, key, plaintext], "CRYPTOMINISAT_EXT"
        )
    assert trail['components_values']['cipher_output_4_12']['value'] == '???????????????0????????????????'



