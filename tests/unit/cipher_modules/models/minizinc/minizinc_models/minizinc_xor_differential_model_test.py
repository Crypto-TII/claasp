from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import \
    MinizincXorDifferentialModel


def test_build_all_xor_differential_trails_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
    minizinc = MinizincXorDifferentialModel(speck)
    bit_positions = [i for i in range(speck.output_bit_size)]
    bit_positions_key = list(range(64))
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
    minizinc.build_lowest_weight_xor_differential_trail_model(fixed_variables)
    result = minizinc.solve('Xor')

    assert result.statistics['nSolutions'] > 1


def test_build_lowest_weight_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
    minizinc = MinizincXorDifferentialModel(speck)
    bit_positions = [i for i in range(speck.output_bit_size)]

    bit_positions_key = list(range(64))
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
    minizinc.build_lowest_weight_xor_differential_trail_model(fixed_variables)
    result = minizinc.solve('Xor')

    assert result.statistics['nSolutions'] > 1


def test_build_lowest_xor_differential_trails_with_at_most_weight():
    speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
    minizinc = MinizincXorDifferentialModel(speck)
    bit_positions = [i for i in range(speck.output_bit_size)]
    bit_positions_key = list(range(64))
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
    minizinc.build_lowest_xor_differential_trails_with_at_most_weight(100, fixed_variables)
    result = minizinc.solve('Xor')

    assert result.statistics['nSolutions'] > 1


def test_find_all_xor_differential_trails_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
    minizinc = MinizincXorDifferentialModel(speck)
    bit_positions = [i for i in range(speck.output_bit_size)]
    bit_positions_key = list(range(64))
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
    result = minizinc.find_all_xor_differential_trails_with_fixed_weight(5, solver_name='Xor',
                                                                         fixed_values=fixed_variables)

    assert result['total_weight'] is None


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = SpeckBlockCipher(number_of_rounds=4, block_bit_size=32, key_bit_size=64)
    minizinc = MinizincXorDifferentialModel(speck)
    bit_positions = list(range(32))
    bit_positions_key = list(range(64))
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
    result = minizinc.find_all_xor_differential_trails_with_weight_at_most(1, solver_name='Xor',
                                                                           fixed_values=fixed_variables)

    assert result[0]['total_weight'] > 1


def test_find_lowest_weight_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
    minizinc = MinizincXorDifferentialModel(speck)
    bit_positions = list(range(32))
    bit_positions_key = list(range(64))
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
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)

    assert result["total_weight"] == 9

    minizinc = MinizincXorDifferentialModel(speck, [0, 0, 0, 0, 0])
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)

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
    bit_positions = list(range(64))
    bit_positions_key = [i for i in range(128)]
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
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    assert result["total_weight"] > 1

    raiden = RaidenBlockCipher(number_of_rounds=2)
    minizinc = MinizincXorDifferentialModel(raiden, sat_or_milp="milp")
    bit_positions = list(range(64))
    bit_positions_key = [i for i in range(128)]
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
    minizinc.build_xor_differential_trail_model(-1, fixed_variables)
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    assert result['total_weight'] == 12

    speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
    pr_weights_per_round = [{"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4}]
    minizinc = MinizincXorDifferentialModel(speck, probability_weight_per_round=pr_weights_per_round)
    bit_positions = [i for i in range(speck.output_bit_size)]
    bit_positions_key = list(range(64))
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
    solution = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    round1_weight = solution['p_modadd_0_1_0']['weight']
    assert 2 <= round1_weight <= 4

    round2_weight = solution['p_modadd_1_2_0']['weight'] + solution['p_modadd_1_7_0']['weight']
    round3_weight = solution['p_modadd_2_2_0']['weight'] + solution['p_modadd_2_7_0']['weight']
    round4_weight = solution['p_modadd_3_2_0']['weight'] + solution['p_modadd_3_7_0']['weight']
    round5_weight = solution['p_modadd_4_2_0']['weight'] + solution['p_modadd_4_7_0']['weight']
    assert 2 <= round2_weight <= 4
    assert 2 <= round3_weight <= 4
    assert 2 <= round4_weight <= 4
    assert 2 <= round5_weight <= 4

    speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
    minizinc = MinizincXorDifferentialModel(speck, sat_or_milp="milp")
    bit_positions = list(range(32))
    bit_positions_key = list(range(64))
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
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    assert result["total_weight"] == 9

    minizinc = MinizincXorDifferentialModel(speck, [0, 0, 0, 0, 0])
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
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
    bit_positions = list(range(64))
    bit_positions_key = [i for i in range(128)]
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
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    assert result["total_weight"] > 1

    raiden = RaidenBlockCipher(number_of_rounds=2)
    minizinc = MinizincXorDifferentialModel(raiden, sat_or_milp="milp")
    bit_positions = list(range(64))
    bit_positions_key = [i for i in range(128)]
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
    minizinc.build_xor_differential_trail_model(-1, fixed_variables)
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    assert result['total_weight'] == 12

    speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
    pr_weights_per_round = [{"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4},
                            {"min_bound": 2, "max_bound": 4}]
    minizinc = MinizincXorDifferentialModel(speck,
                                            probability_weight_per_round=pr_weights_per_round,
                                            sat_or_milp="milp")
    bit_positions = [i for i in range(speck.output_bit_size)]
    bit_positions_key = list(range(64))
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
    solution = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    round1_weight = solution['p_modadd_0_1_0']['weight']
    assert 2 <= round1_weight <= 4

    round2_weight = solution['p_modadd_1_2_0']['weight'] + solution['p_modadd_1_7_0']['weight']
    round3_weight = solution['p_modadd_2_2_0']['weight'] + solution['p_modadd_2_7_0']['weight']
    round4_weight = solution['p_modadd_3_2_0']['weight'] + solution['p_modadd_3_7_0']['weight']
    round5_weight = solution['p_modadd_4_2_0']['weight'] + solution['p_modadd_4_7_0']['weight']
    assert 2 <= round2_weight <= 4
    assert 2 <= round3_weight <= 4
    assert 2 <= round4_weight <= 4
    assert 2 <= round5_weight <= 4


def test_find_lowest_weight_for_short_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=4, block_bit_size=32, key_bit_size=64)
    minizinc = MinizincXorDifferentialModel(speck)
    bit_positions = list(range(32))
    bit_positions_key = list(range(64))
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
    minizinc.set_max_number_of_carries_on_arx_cipher(0)
    minizinc.set_max_number_of_nonlinear_carries(0)
    result = minizinc.find_lowest_weight_xor_differential_trail(solver_name='Xor', fixed_values=fixed_variables)
    assert result["total_weight"] == 5
