import numpy as np

from claasp.components.modadd_component import MODADD
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.sat.solvers import CADICAL_EXT, KISSAT_EXT, PARKISSAT_EXT


def count_sequences_of_ones(data, full_window_size):
    count = 0
    for entry in data:
        for binary_str in entry.values():
            binary_str = binary_str[2:]  # Remove the '0b' prefix
            sequences = binary_str.split("0")
            for seq in sequences:
                if len(seq) >= full_window_size:
                    count += len(seq) - full_window_size + 1  # Count overlapping sequences
    return count


def binary_list_to_int(binary_list):
    result = 0
    for bit in binary_list:
        result = (result << 1) | bit
    return result


def extract_bits_from_hex(hex_value, bit_positions):
    hex_value = int(f"{hex_value}", 16)
    bin_values = []

    last_bit_position = bit_positions[-1]
    for bit_position in bit_positions:
        bit_value = 1 & (hex_value >> (last_bit_position - bit_position))
        bin_values.append(bit_value)
    extracted_value = binary_list_to_int(bin_values)

    return extracted_value


def compute_modadd_xor(modadd_objects, component_values):
    result = []
    for modadd in modadd_objects:
        modadd_id = modadd.id
        input_id_links = modadd.input_id_links
        input_bit_positions = modadd.input_bit_positions

        # Get the output value of the MODADD component
        output_value = component_values[modadd_id]["value"]

        # Initialize the XOR result with the output value
        xor_result = int(f"{output_value}", 16)

        # XOR all input values based on bit positions
        for input_id, bit_positions in zip(input_id_links, input_bit_positions):
            input_value = component_values[input_id]["value"]

            extracted_bits_number = extract_bits_from_hex(input_value, bit_positions)
            xor_result ^= extracted_bits_number

        result.append({f"{modadd_id}": bin(xor_result)})
    return result


speck_5rounds = SpeckBlockCipher(number_of_rounds=5)
speck_4rounds = SpeckBlockCipher(number_of_rounds=4)


def test_find_all_xor_differential_trails_with_fixed_weight():
    sat = SatXorDifferentialModel(speck_5rounds)
    sat.set_window_size_weight_pr_vars(1)

    assert int(sat.find_all_xor_differential_trails_with_fixed_weight(9)[0]["total_weight"]) == 9


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = speck_5rounds
    sat = SatXorDifferentialModel(speck)
    trails = sat.find_all_xor_differential_trails_with_weight_at_most(9, 10)

    assert len(trails) == 28


def test_find_lowest_weight_xor_differential_trail():
    speck = speck_5rounds
    sat = SatXorDifferentialModel(speck, counter='parallel')
    trail = sat.find_lowest_weight_xor_differential_trail()

    assert int(trail["total_weight"]) == 9


def test_find_one_xor_differential_trail():
    speck = speck_5rounds
    sat = SatXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id="plaintext",
        constraint_type="not_equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0, 32, "big"),
    )
    trail = sat.find_one_xor_differential_trail(fixed_values=[plaintext])

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r5"
    assert trail["model_type"] == "xor_differential"
    assert trail["status"] == "SATISFIABLE"

    trail = sat.find_one_xor_differential_trail(fixed_values=[plaintext], solver_name=KISSAT_EXT)

    assert trail["status"] == "SATISFIABLE"


def test_find_one_xor_differential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorDifferentialModel(speck)
    sat.set_window_size_heuristic_by_round([0, 0, 0])
    result = sat.find_one_xor_differential_trail_with_fixed_weight(3)

    assert int(result["total_weight"]) == int(3.0)


def test_find_one_xor_differential_trail_with_fixed_weight_with_at_least_one_full_2_window():
    speck = SpeckBlockCipher(number_of_rounds=9)
    sat = SatXorDifferentialModel(speck)
    sat.set_window_size_heuristic_by_round([2 for _ in range(9)], number_of_full_windows=1)
    result = sat.find_one_xor_differential_trail_with_fixed_weight(30, solver_name=CADICAL_EXT)

    assert int(result["total_weight"]) == int(30.0)


def test_find_one_xor_differential_trail_with_fixed_weight_and_with_exactly_three_full_2_window():
    speck = SpeckBlockCipher(number_of_rounds=9)
    sat = SatXorDifferentialModel(speck)
    number_of_full_windows = 3
    window_size = 2
    sat.set_window_size_heuristic_by_round(
        [window_size for _ in range(9)], number_of_full_windows=number_of_full_windows
    )
    result = sat.find_one_xor_differential_trail_with_fixed_weight(30, solver_name=CADICAL_EXT)
    speck_components = speck.get_all_components()
    modadd_objects = list(filter(lambda obj: isinstance(obj, MODADD), speck_components))

    carry_list = compute_modadd_xor(modadd_objects, result["components_values"])
    computed_number_of_full_windows = count_sequences_of_ones(carry_list, window_size)

    assert int(result["total_weight"]) == int(30.0)
    assert computed_number_of_full_windows == number_of_full_windows


def test_find_one_xor_differential_trail_with_fixed_weight_and_with_exactly_one_full_3_window():
    speck = SpeckBlockCipher(number_of_rounds=10)
    sat = SatXorDifferentialModel(speck)
    number_of_full_windows = 1
    window_size = 3
    probability_weight = 34
    sat.set_window_size_heuristic_by_round(
        [window_size for _ in range(10)], number_of_full_windows=number_of_full_windows, full_window_operator="exactly"
    )

    plaintext = set_fixed_variables(
        component_id="plaintext",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    key = set_fixed_variables(
        component_id="key", constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    sat.build_xor_differential_trail_model(34, fixed_variables=[plaintext, key])
    result = sat._solve_with_external_sat_solver("xor_differential", PARKISSAT_EXT, ["-c=6"])
    speck_components = speck.get_all_components()
    modadd_objects = list(filter(lambda obj: isinstance(obj, MODADD), speck_components))
    carry_list = compute_modadd_xor(modadd_objects, result["components_values"])
    computed_number_of_full_windows = count_sequences_of_ones(carry_list, window_size)

    assert int(result["total_weight"]) == int(probability_weight)
    assert computed_number_of_full_windows == number_of_full_windows


def test_find_one_xor_differential_trail_with_fixed_weight_9_rounds():
    speck = SpeckBlockCipher(number_of_rounds=9)
    sat = SatXorDifferentialModel(speck)

    sat.set_window_size_heuristic_by_round([2 for _ in range(9)])
    result = sat.find_one_xor_differential_trail_with_fixed_weight(30, solver_name=CADICAL_EXT)

    assert int(result["total_weight"]) == int(30.0)


def test_find_one_xor_differential_trail_with_fixed_weight_with_at_least_one_full_window_parallel():
    speck = SpeckBlockCipher(number_of_rounds=10)
    sat = SatXorDifferentialModel(speck)
    sat.set_window_size_heuristic_by_round([3 for _ in range(10)], number_of_full_windows=1)
    plaintext = set_fixed_variables(
        component_id="plaintext",
        constraint_type="not_equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0, 32, "big"),
    )
    key = set_fixed_variables(
        component_id="key", constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    sat.build_xor_differential_trail_model(34, fixed_variables=[plaintext, key])
    result = sat._solve_with_external_sat_solver("xor_differential", PARKISSAT_EXT, ["-c=10"])

    assert int(result["total_weight"]) == int(34.0)


def test_find_one_xor_differential_trail_with_fixed_weight_and_window_heuristic_per_component():
    speck = SpeckBlockCipher(number_of_rounds=3)
    filtered_objects = [obj.id for obj in speck.get_all_components() if obj.description[0] == "MODADD"]
    dict_of_window_heuristic_per_component = {}
    for component_id in filtered_objects:
        dict_of_window_heuristic_per_component[component_id] = 0
    sat = SatXorDifferentialModel(speck)
    sat.set_window_size_heuristic_by_component_id(dict_of_window_heuristic_per_component)
    result = sat.find_one_xor_differential_trail_with_fixed_weight(3)

    assert int(result["total_weight"]) == int(3.0)


def test_build_xor_differential_trail_model_fixed_weight_and_parkissat():
    number_of_cores = 2
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorDifferentialModel(speck)
    sat.build_xor_differential_trail_model(3)
    result = sat._solve_with_external_sat_solver("xor_differential", PARKISSAT_EXT, [f"-c={number_of_cores}"])

    assert int(result["total_weight"]) == int(3.0)


def repeat_input_difference(input_difference_, number_of_samples_, number_of_bytes_):
    bytes_array = input_difference_.to_bytes(number_of_bytes_, "big")
    np_array = np.array(list(bytes_array), dtype=np.uint8)
    column_array = np_array.reshape(-1, 1)

    return np.tile(column_array, (1, number_of_samples_))
