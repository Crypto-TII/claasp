from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import (
    SatSemiDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.sat.solvers import CADICAL_EXT
from claasp.cipher_modules.models.utils import (
    set_fixed_variables,
    differential_truncated_checker_permutation,
    integer_to_bit_list,
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY


def test_find_one_semi_deterministic_truncated_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
    bit_values = [0] * 32
    bit_values[10] = 1
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="equal", bit_positions=range(32), bit_values=bit_values
    )

    intermediate_output_0_6 = set_fixed_variables(
        component_id="intermediate_output_0_6",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id="intermediate_output_1_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[0, 2, 2, 2, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1],
    )

    cipher_output_2_12 = set_fixed_variables(
        component_id="cipher_output_2_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, intermediate_output_0_6, intermediate_output_1_12, cipher_output_2_12, key]
    )

    assert trail["components_values"]["cipher_output_2_12"]["value"] == "???????????????0????????????????"


def test_find_one_semi_deterministic_truncated_xor_differential_trail_with_window_size_configuration():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )

    intermediate_output_0_6 = set_fixed_variables(
        component_id="intermediate_output_0_6",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id="intermediate_output_1_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[0, 1, 0, 0, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1],
    )

    cipher_output_2_12 = set_fixed_variables(
        component_id="cipher_output_2_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1],
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, intermediate_output_0_6, intermediate_output_1_12, cipher_output_2_12, key],
        unknown_window_size_configuration={
            "max_number_of_sequences_window_size_0": 20,
            "max_number_of_sequences_window_size_1": 20,
            "max_number_of_sequences_window_size_2": 20,
        },
    )

    assert trail["components_values"]["cipher_output_2_12"]["value"] == "????0??????????0???????????????1"


def test_find_one_semi_deterministic_truncated_xor_differential_trail_with_window_size_configuration_unsat():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )

    intermediate_output_0_6 = set_fixed_variables(
        component_id="intermediate_output_0_6",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id="intermediate_output_1_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[0, 1, 0, 0, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1],
    )

    cipher_output_2_12 = set_fixed_variables(
        component_id="cipher_output_2_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1],
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, intermediate_output_0_6, intermediate_output_1_12, cipher_output_2_12, key],
        unknown_window_size_configuration={
            "max_number_of_sequences_window_size_0": 20,
            "max_number_of_sequences_window_size_1": 1,
            "max_number_of_sequences_window_size_2": 20,
        },
    )

    assert trail["status"] == "UNSATISFIABLE"


def test_find_one_semi_deterministic_truncated_xor_differential_trail_with_window_size_configuration_chacha():
    chacha = ChachaPermutation(number_of_rounds=6)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(chacha)
    state_size = 512
    initial_state = [0] * state_size
    initial_state[389] = 1
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="equal", bit_positions=range(state_size), bit_values=initial_state
    )

    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext],
        unknown_window_size_configuration={
            "max_number_of_sequences_window_size_0": 20,
            "max_number_of_sequences_window_size_1": 1,
            "max_number_of_sequences_window_size_2": 20,
        },
    )

    assert trail["status"] == "UNSATISFIABLE"


def test_find_one_semi_deterministic_truncated_xor_differential_trail_with_window_size_for_chacha_1_round_satisfiable():
    chacha = ChachaPermutation(number_of_rounds=2)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(chacha)
    state_size = 512
    initial_state_positions = [0] * state_size
    initial_state_positions[508] = 1

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=initial_state_positions,
    )

    intermediate_output_0_24_int = 0x00000000000000000000000000000000000000000000000000000000800000000000000000000000000000000008000000000000000000000000000000080000
    intermediate_output_0_24 = set_fixed_variables(
        component_id="intermediate_output_0_24",
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(intermediate_output_0_24_int, state_size, "big"),
    )

    cipher_output_1_24_int = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000010000000????100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000????100000001000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000010000000"
    cipher_output_1_24_int_temp = list(map(int, cipher_output_1_24_int.replace("?", "2")))
    cipher_output_1_24 = set_fixed_variables(
        component_id="cipher_output_1_24",
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=cipher_output_1_24_int_temp,
    )

    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, intermediate_output_0_24, cipher_output_1_24],
        unknown_window_size_configuration={
            "max_number_of_sequences_window_size_0": 3,
            "max_number_of_sequences_window_size_1": 3,
            "max_number_of_sequences_window_size_2": 3,
        },
        number_of_unknowns_per_component={"cipher_output_1_24": 8},
        solver_name=CADICAL_EXT,
    )

    assert trail["status"] == "SATISFIABLE"

    input_difference = int(trail["components_values"][INPUT_PLAINTEXT]["value"], 2)
    output_difference = trail["components_values"]["cipher_output_1_24"]["value"]
    prob = differential_truncated_checker_permutation(
        chacha, input_difference, output_difference, 1 << 12, state_size, seed=42
    )
    assert 0 < abs(prob) < 5
