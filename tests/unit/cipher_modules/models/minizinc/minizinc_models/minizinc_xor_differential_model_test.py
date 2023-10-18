from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import \
    MinizincXorDifferentialModel

speck4 = SpeckBlockCipher(number_of_rounds=4, block_bit_size=32, key_bit_size=64)
minizinc4 = MinizincXorDifferentialModel(speck4)

speck5 = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
minizinc5 = MinizincXorDifferentialModel(speck5)


def generate_fixed_variables(block_size, key_size):
    bit_positions = list(range(block_size))
    bit_positions_key = list(range(key_size))
    fixed_variables = [{'component_id': 'plaintext',
                        'constraint_type': 'sum',
                        'bit_positions': bit_positions,
                        'operator': '>',
                        'value': '0'},
                       {'component_id': 'key',
                        'constraint_type': 'sum',
                        'bit_positions': bit_positions_key,
                        'operator': '=',
                        'value': '0'}]
    return fixed_variables


fixed_variables_32_64 = generate_fixed_variables(32, 64)
fixed_variables_64_128 = generate_fixed_variables(64, 128)


def test_build_lowest_weight_xor_differential_trail_model():
    minizinc5.build_lowest_weight_xor_differential_trail_model(fixed_variables_32_64)
    result = minizinc5.solve('Xor')
    assert result.statistics['nSolutions'] > 1


def test_build_lowest_xor_differential_trails_with_at_most_weight():
    minizinc5.build_lowest_xor_differential_trails_with_at_most_weight(100, fixed_variables_32_64)
    result = minizinc5.solve('Xor')

    assert result.statistics['nSolutions'] > 1


def test_find_all_xor_differential_trails_with_fixed_weight():
    result = minizinc5.find_all_xor_differential_trails_with_fixed_weight(
        5, solver_name='Xor', fixed_values=fixed_variables_32_64)

    assert result['total_weight'] is None


def test_find_all_xor_differential_trails_with_weight_at_most():
    result = minizinc4.find_all_xor_differential_trails_with_weight_at_most(
        1, solver_name='Xor', fixed_values=fixed_variables_32_64
    )
    assert result[0]['total_weight'] > 1


def test_find_lowest_weight_xor_differential_trail():
    result = minizinc5.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_32_64)
    assert result["total_weight"] == 9

    minizinc = MinizincXorDifferentialModel(speck5, [0, 0, 0, 0, 0])
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_32_64)
    assert result["total_weight"] == 9

    speck = SpeckBlockCipher(number_of_rounds=4)
    minizinc = MinizincXorDifferentialModel(speck)
    bit_positions_key = list(range(64))
    fixed_variables = [{'component_id': 'key',
                        'constraint_type': 'sum',
                        'bit_positions': bit_positions_key,
                        'operator': '>',
                        'value': '0'}]
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    assert result["total_weight"] == 0

    tea = TeaBlockCipher(number_of_rounds=2)
    minizinc = MinizincXorDifferentialModel(tea)
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_64_128)
    assert result["total_weight"] > 1

    raiden = RaidenBlockCipher(number_of_rounds=2)
    minizinc = MinizincXorDifferentialModel(raiden, sat_or_milp="milp")
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_64_128)
    assert result['total_weight'] == 6

    pr_weights_per_round = [{"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4}]
    minizinc = MinizincXorDifferentialModel(speck5, probability_weight_per_round=pr_weights_per_round)
    solution = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_32_64)
    round1_weight = solution['component_values']['modadd_0_1']['weight']
    assert 2 <= round1_weight <= 4
    component_values = solution['component_values']
    round2_weight = component_values['modadd_1_2']['weight'] + component_values['modadd_1_7']['weight']
    round3_weight = component_values['modadd_2_2']['weight'] + component_values['modadd_2_7']['weight']
    round4_weight = component_values['modadd_3_2']['weight'] + component_values['modadd_3_7']['weight']
    round5_weight = component_values['modadd_4_2']['weight'] + component_values['modadd_4_7']['weight']
    assert 2 <= round2_weight <= 4
    assert 2 <= round3_weight <= 4
    assert 2 <= round4_weight <= 4
    assert 2 <= round5_weight <= 4

    minizinc = MinizincXorDifferentialModel(speck5, sat_or_milp="milp")
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_32_64)
    assert result["total_weight"] == 9

    minizinc = MinizincXorDifferentialModel(speck5, [0, 0, 0, 0, 0])
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_32_64)
    assert result["total_weight"] == 9

    speck = SpeckBlockCipher(number_of_rounds=4)
    minizinc = MinizincXorDifferentialModel(speck, sat_or_milp="milp")
    bit_positions_key = list(range(64))
    fixed_variables = [{'component_id': 'key',
                        'constraint_type': 'sum',
                        'bit_positions': bit_positions_key,
                        'operator': '>',
                        'value': '0'}]
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    assert result["total_weight"] == 0

    tea = TeaBlockCipher(number_of_rounds=2)
    minizinc = MinizincXorDifferentialModel(tea, sat_or_milp="milp")
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_64_128)
    assert result["total_weight"] > 1

    raiden = RaidenBlockCipher(number_of_rounds=2)
    minizinc = MinizincXorDifferentialModel(raiden, sat_or_milp="milp")
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_64_128)
    assert result['total_weight'] == 6

    pr_weights_per_round = [{"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4}]
    minizinc = MinizincXorDifferentialModel(speck5,
                                            probability_weight_per_round=pr_weights_per_round,
                                            sat_or_milp="milp")
    solution = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_32_64)
    round1_weight = solution['component_values']['modadd_0_1']['weight']
    assert 2 <= round1_weight <= 4
    component_values = solution['component_values']
    round2_weight = component_values['modadd_1_2']['weight'] + component_values['modadd_1_7']['weight']
    round3_weight = component_values['modadd_2_2']['weight'] + component_values['modadd_2_7']['weight']
    round4_weight = component_values['modadd_3_2']['weight'] + component_values['modadd_3_7']['weight']
    round5_weight = component_values['modadd_4_2']['weight'] + component_values['modadd_4_7']['weight']
    assert 2 <= round2_weight <= 4
    assert 2 <= round3_weight <= 4
    assert 2 <= round4_weight <= 4
    assert 2 <= round5_weight <= 4


def test_find_lowest_weight_for_short_xor_differential_trail():
    minizinc4.set_max_number_of_carries_on_arx_cipher(0)
    minizinc4.set_max_number_of_nonlinear_carries(0)
    result = minizinc4.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables_32_64)
    assert result["total_weight"] == 5


def test_get_probability_vars_from_key_schedule():
    minizinc = MinizincXorDifferentialModel(speck4)
    minizinc.build_xor_differential_trail_model(fixed_variables=[])
    expected_result = ['p_modadd_1_2_0', 'p_modadd_2_2_0', 'p_modadd_3_2_0']
    assert minizinc.get_probability_vars_from_key_schedule() == expected_result


def test_get_probability_vars_from_permutation():
    minizinc = MinizincXorDifferentialModel(speck4)
    minizinc.build_xor_differential_trail_model(fixed_variables=[])
    expected_result = ['p_modadd_0_1_0', 'p_modadd_1_7_0', 'p_modadd_2_7_0', 'p_modadd_3_7_0']
    assert minizinc.get_probability_vars_from_permutation() == expected_result


def test_find_min_of_max_xor_differential_between_permutation_and_key_schedule():
    minizinc = MinizincXorDifferentialModel(speck4)
    result = minizinc.find_min_of_max_xor_differential_between_permutation_and_key_schedule(
        fixed_values=fixed_variables_32_64, solver_name='Xor'
    )
    print(result)
