from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values, set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import \
    MilpBitwiseDeterministicTruncatedXorDifferentialModel


def test_build_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
    milp.init_model_in_sage_milp_class()
    milp.build_deterministic_truncated_xor_differential_trail_model()
    constraints = milp.model_constraints

    assert len(constraints) == 62624
    assert str(constraints[0]) == 'x_16 == x_9'
    assert str(constraints[1]) == 'x_17 == x_10'
    assert str(constraints[-2]) == 'x_13273 == x_13225'
    assert str(constraints[-1]) == 'x_13274 == x_13226'

def test_find_one_bitwise_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
                                          bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0,
                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    trail = milp.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
    assert trail['components_values']['intermediate_output_0_6']['value'] == '22221000000000002222100000000011'


    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32),
                                          bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    trail = milp.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
    assert trail['components_values']['cipher_output_2_12']['value'] == '22222222222222202222222222222222'


def test_find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
    trail = milp.find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(
        get_single_key_scenario_format_for_fixed_values(speck))
    assert trail['status'] == 'SATISFIABLE'
    assert trail['total_weight'] == 14.0
