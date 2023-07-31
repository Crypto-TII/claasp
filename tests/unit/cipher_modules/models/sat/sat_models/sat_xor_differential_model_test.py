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

    assert sat.find_all_xor_differential_trails_with_fixed_weight(
        9, fixed_values=[plaintext, key])[0]['total_weight'] == 9.0


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

    assert trail['total_weight'] == 9.0


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
    sat = SatXorDifferentialModel(speck, window_size=0)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=(0,) * 32)
    key = set_fixed_variables(component_id='key', constraint_type='equal',
                              bit_positions=range(64), bit_values=(0,) * 64)
    result = sat.find_one_xor_differential_trail_with_fixed_weight(3, fixed_values=[plaintext, key])

    assert result['total_weight'] == 3.0


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

    assert result['total_weight'] == 3.0
