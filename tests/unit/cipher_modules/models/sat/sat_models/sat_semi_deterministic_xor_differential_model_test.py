from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import \
    SatSemiDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation


def test_find_one_semi_deterministic_truncated_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
    bit_values = [0]*32
    bit_values[10] = 1
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
                                    bit_values=bit_values)

    intermediate_output_0_6 = set_fixed_variables(
        component_id='intermediate_output_0_6', constraint_type='equal', bit_positions=range(32),
        bit_values=[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    intermediate_output_1_12 = set_fixed_variables(
        component_id='intermediate_output_1_12', constraint_type='equal', bit_positions=range(32),
        bit_values=[0, 2, 2, 2, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1])

    cipher_output_2_12 = set_fixed_variables(
        component_id='cipher_output_2_12', constraint_type='equal', bit_positions=range(32),
        bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])

    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64),
                              bit_values=(0,) * 64)
    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, intermediate_output_0_6, intermediate_output_1_12, cipher_output_2_12, key]
    )

    assert trail['components_values']['cipher_output_2_12']['value'] == '???????????????0????????????????'


def test_find_one_semi_deterministic_truncated_xor_differential_trail_with_window_size_configuration():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)

    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
                                    bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0])

    intermediate_output_0_6 = set_fixed_variables(
        component_id='intermediate_output_0_6', constraint_type='equal', bit_positions=range(32),
        bit_values=[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    intermediate_output_1_12 = set_fixed_variables(
        component_id='intermediate_output_1_12', constraint_type='equal', bit_positions=range(32),
        bit_values=[0, 1, 0, 0, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1])

    cipher_output_2_12 = set_fixed_variables(
        component_id='cipher_output_2_12', constraint_type='equal', bit_positions=range(32),
        bit_values=[2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1])

    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64),
                              bit_values=(0,) * 64)
    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, intermediate_output_0_6, intermediate_output_1_12, cipher_output_2_12, key],
        unknown_probability_weight_configuration={
            "max_number_of_sequences_window_size_0": 20,
            "max_number_of_sequences_window_size_1": 20,
            "max_number_of_sequences_window_size_2": 20
        }
    )

    print(trail)

    assert trail['components_values']['cipher_output_2_12']['value'] == '????0??????????0???????????????1'


def test_find_one_semi_deterministic_truncated_xor_differential_trail_with_window_size_configuration_unsat():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)

    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
                                    bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0])

    intermediate_output_0_6 = set_fixed_variables(
        component_id='intermediate_output_0_6', constraint_type='equal', bit_positions=range(32),
        bit_values=[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    intermediate_output_1_12 = set_fixed_variables(
        component_id='intermediate_output_1_12', constraint_type='equal', bit_positions=range(32),
        bit_values=[0, 1, 0, 0, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 2, 2, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1])

    cipher_output_2_12 = set_fixed_variables(
        component_id='cipher_output_2_12', constraint_type='equal', bit_positions=range(32),
        bit_values=[2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1])

    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64),
                              bit_values=(0,) * 64)
    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, intermediate_output_0_6, intermediate_output_1_12, cipher_output_2_12, key],
        unknown_probability_weight_configuration={
            "max_number_of_sequences_window_size_0": 20,
            "max_number_of_sequences_window_size_1": 1,
            "max_number_of_sequences_window_size_2": 20
        }
    )

    assert trail['status'] == 'UNSATISFIABLE'


def test_find_one_semi_deterministic_truncated_xor_differential_trail_with_window_size_configuration_chacha():
    chacha = ChachaPermutation(number_of_rounds=6)
    sat = SatSemiDeterministicTruncatedXorDifferentialModel(chacha)
    state_size = 512
    initial_state = [0] * state_size
    initial_state[389] = 1
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(state_size),
                                    bit_values=initial_state)

    trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext],
        unknown_probability_weight_configuration={
            "max_number_of_sequences_window_size_0": 20,
            "max_number_of_sequences_window_size_1": 1,
            "max_number_of_sequences_window_size_2": 20
        }
    )

    assert trail['status'] == 'UNSATISFIABLE'
