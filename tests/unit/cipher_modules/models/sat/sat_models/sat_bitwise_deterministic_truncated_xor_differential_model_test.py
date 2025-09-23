from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import (
    SatBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values, set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, SATISFIABLE


def test_build_bitwise_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    sat = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
    sat.build_bitwise_deterministic_truncated_xor_differential_trail_model()
    constraints = sat.model_constraints

    assert len(constraints) == 28761
    assert str(constraints[0]) == "rot_0_0_0_0 -plaintext_9_0"
    assert str(constraints[1]) == "plaintext_9_0 -rot_0_0_0_0"
    assert str(constraints[-2]) == "cipher_output_21_12_31_1 -xor_21_10_15_1"
    assert str(constraints[-1]) == "xor_21_10_15_1 -cipher_output_21_12_31_1"


def test_find_one_bitwise_deterministic_truncated_xor_differential_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    sat = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    trail = sat.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
    assert trail["components_values"]["intermediate_output_0_6"]["value"] == "????100000000000????100000000011"

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
    sat = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    trail = sat.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
    assert trail["components_values"]["cipher_output_2_12"]["value"] == "???????????????0????????????????"


def test_find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    sat = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
    trail = sat.find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(
        get_single_key_scenario_format_for_fixed_values(speck)
    )
    assert trail["status"] == SATISFIABLE
