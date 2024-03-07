import numpy as np

from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel

def test_find_all_xor_differential_trails_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=5)
    sat = SatXorDifferentialModel(speck, window_size_weight_pr_vars=1)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=(0,) * 32)
    key = set_fixed_variables(component_id='key', constraint_type='equal',
                              bit_positions=range(64), bit_values=(0,) * 64)

    assert int(sat.find_all_xor_differential_trails_with_fixed_weight(
        9, fixed_values=[plaintext, key])[0]['total_weight']) == int(9.0)


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = SpeckBlockCipher(number_of_rounds=5)
    sat = SatXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=integer_to_bit_list(0, 32, 'big'))
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64),
                              bit_values=integer_to_bit_list(0, 64, 'big'))
    trails = sat.find_all_xor_differential_trails_with_weight_at_most(9, 10, fixed_values=[plaintext, key])

    assert len(trails) == 28


def test_find_lowest_weight_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    sat = SatXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=(0,) * 32)
    key = set_fixed_variables(component_id='key', constraint_type='equal',
                              bit_positions=range(64), bit_values=(0,) * 64)
    trail = sat.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])

    assert int(trail['total_weight']) == int(9.0)


def test_find_one_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    sat = SatXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=integer_to_bit_list(0, 32, 'big'))
    trail = sat.find_one_xor_differential_trail(fixed_values=[plaintext])

    assert trail['cipher_id'] == 'speck_p32_k64_o32_r5'
    assert trail['model_type'] == 'xor_differential'
    assert trail['solver_name'] == 'cryptominisat'
    assert trail['status'] == 'SATISFIABLE'

    trail = sat.find_one_xor_differential_trail(fixed_values=[plaintext], solver_name="kissat")
    assert trail['solver_name'] == 'kissat'
    assert trail['status'] == 'SATISFIABLE'


def test_find_one_xor_differential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorDifferentialModel(speck, window_size_by_round=[0, 0, 0])
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=(0,) * 32)
    key = set_fixed_variables(component_id='key', constraint_type='equal',
                              bit_positions=range(64), bit_values=(0,) * 64)
    result = sat.find_one_xor_differential_trail_with_fixed_weight(3, fixed_values=[plaintext, key])

    assert int(result['total_weight']) == int(3.0)


def test_find_one_xor_differential_trail_with_fixed_weight_and_window_heuristic_per_component():
    speck = SpeckBlockCipher(number_of_rounds=3)
    filtered_objects = [obj.id for obj in speck.get_all_components() if obj.description[0] == "MODADD"]
    dict_of_window_heuristic_per_component = {}
    for component_id in filtered_objects:
        dict_of_window_heuristic_per_component[component_id] = 0
    sat = SatXorDifferentialModel(speck, window_size_by_component_id=dict_of_window_heuristic_per_component)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=(0,) * 32)
    key = set_fixed_variables(component_id='key', constraint_type='equal',
                              bit_positions=range(64), bit_values=(0,) * 64)
    result = sat.find_one_xor_differential_trail_with_fixed_weight(3, fixed_values=[plaintext, key])
    assert int(result['total_weight']) == int(3.0)


def test_build_xor_differential_trail_model_fixed_weight_and_parkissat():
    number_of_cores = 2
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0, 32, 'big'))
    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64)
    sat.build_xor_differential_trail_model(3, fixed_variables=[plaintext, key])
    result = sat._solve_with_external_sat_solver("xor_differential", "parkissat", [f'-c={number_of_cores}'])

    assert int(result['total_weight']) == int(3.0)

def test_differential_in_related_key_scenario_speck3264():
    def repeat_input_difference(input_difference_, number_of_samples_, number_of_bytes_):
        bytes_array = input_difference_.to_bytes(number_of_bytes_, 'big')
        np_array = np.array(list(bytes_array), dtype=np.uint8)
        column_array = np_array.reshape(-1, 1)
        return np.tile(column_array, (1, number_of_samples_))

    rng = np.random.default_rng(seed=42)
    number_of_samples = 2**22
    input_difference = 0x2a14001
    output_difference = 0x850a810a
    key_difference = 0x2800020000800001
    input_difference_data = repeat_input_difference(input_difference, number_of_samples, 4)
    output_difference_data = repeat_input_difference(output_difference, number_of_samples, 4)
    key_difference_data = repeat_input_difference(key_difference, number_of_samples, 8)
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=7)
    key_data = rng.integers(low=0, high=256, size=(8, number_of_samples), dtype=np.uint8)

    plaintext_data1 = rng.integers(low=0, high=256, size=(4, number_of_samples), dtype=np.uint8)
    plaintext_data2 = plaintext_data1 ^ input_difference_data
    ciphertext1 = speck.evaluate_vectorized([plaintext_data1, key_data])
    ciphertext2 = speck.evaluate_vectorized([plaintext_data2, key_data ^ key_difference_data])
    total = np.sum(ciphertext1[0] ^ ciphertext2[0] == output_difference_data.T)
    import math
    total_prob_weight = math.log(total, 2)
    assert 18 > total_prob_weight > 12

def test_differential_in_single_key_scenario_speck3264():
    def repeat_input_difference(input_difference_, number_of_samples_, number_of_bytes_):
        bytes_array = input_difference_.to_bytes(number_of_bytes_, 'big')
        np_array = np.array(list(bytes_array), dtype=np.uint8)
        column_array = np_array.reshape(-1, 1)
        return np.tile(column_array, (1, number_of_samples_))

    rng = np.random.default_rng(seed=42)
    number_of_samples = 2**22
    input_difference = 0x20400040
    output_difference = 0x106040E0
    input_difference_data = repeat_input_difference(input_difference, number_of_samples, 4)
    output_difference_data = repeat_input_difference(output_difference, number_of_samples, 4)
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=5)
    key_data = rng.integers(low=0, high=256, size=(8, number_of_samples), dtype=np.uint8)
    plaintext_data1 = rng.integers(low=0, high=256, size=(4, number_of_samples), dtype=np.uint8)
    plaintext_data2 = plaintext_data1 ^ input_difference_data
    ciphertext1 = speck.evaluate_vectorized([plaintext_data1, key_data])
    ciphertext2 = speck.evaluate_vectorized([plaintext_data2, key_data])
    total = np.sum(ciphertext1[0] ^ ciphertext2[0] == output_difference_data.T)
    import math
    total_prob_weight = math.log(total, 2)
    assert 21 > total_prob_weight > 13