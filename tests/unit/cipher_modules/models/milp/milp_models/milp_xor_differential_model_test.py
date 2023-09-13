from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher


def test_find_all_xor_differential_trails_with_fixed_weight():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trail = milp.find_all_xor_differential_trails_with_fixed_weight(
        1, get_single_key_scenario_format_for_fixed_values(speck))

    assert len(trail) == 6
    for i in range(len(trail)):
        assert trail[i]['cipher_id'] == 'speck_p8_k16_o8_r2'
        assert trail[i]['total_weight'] == 1.0
        assert eval(trail[i]['components_values']['plaintext']['value']) > 0
        assert eval(trail[i]['components_values']['key']['value']) == 0
        assert eval(trail[i]['components_values']['modadd_0_1']['value']) >= 0
        assert trail[i]['components_values']['modadd_0_1']['weight'] >= 0.0
        assert trail[i]['components_values']['modadd_0_1']['sign'] == 1
        assert eval(trail[i]['components_values']['intermediate_output_0_6']['value']) >= 0
        assert trail[i]['components_values']['intermediate_output_0_6']['weight'] == 0
        assert trail[i]['components_values']['intermediate_output_0_6']['sign'] == 1


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trails = milp.find_all_xor_differential_trails_with_weight_at_most(
        0, 1, get_single_key_scenario_format_for_fixed_values(speck))
    assert len(trails) == 7
    for i in range(len(trails)):
        assert trails[i]['total_weight'] <= 1.0
        assert trails[i]['total_weight'] >= 0.0


def test_find_lowest_weight_xor_differential_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trail = milp.find_lowest_weight_xor_differential_trail(
        get_single_key_scenario_format_for_fixed_values(speck))
    assert trail["total_weight"] == 1.0

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck, n_window_heuristic=3)
    trail = milp.find_lowest_weight_xor_differential_trail(
        get_single_key_scenario_format_for_fixed_values(speck))
    assert trail["total_weight"] == 1.0

    present = PresentBlockCipher(number_of_rounds=2)
    milp = MilpXorDifferentialModel(present)
    trail = milp.find_lowest_weight_xor_differential_trail(
        get_single_key_scenario_format_for_fixed_values(present))
    assert trail["total_weight"] == 4.0


def test_find_one_xor_differential_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trail = milp.find_one_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(speck))
    assert trail["total_weight"] >= 1.0

    tea = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
    milp = MilpXorDifferentialModel(tea)
    trail = milp.find_one_xor_differential_trail()
    assert trail["total_weight"] >= 0.0

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trail = milp.find_one_xor_differential_trail()
    assert trail["total_weight"] >= 0.0


def test_find_one_xor_differential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    fixed_values = get_single_key_scenario_format_for_fixed_values(speck)
    trail = milp.find_one_xor_differential_trail_with_fixed_weight(5, fixed_values)
    assert trail["total_weight"] == 5.0

    tea = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
    milp = MilpXorDifferentialModel(tea)
    trail = milp.find_one_xor_differential_trail_with_fixed_weight(15)
    assert trail["total_weight"] == 15.0
    #
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trail = milp.find_one_xor_differential_trail_with_fixed_weight(5)
    assert trail["total_weight"] == 5.0
