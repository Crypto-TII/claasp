from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT


def test_find_all_xor_differential_trails_with_fixed_weight():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trails = milp.find_all_xor_differential_trails_with_fixed_weight(1)

    assert len(trails) == 6
    for trail in trails:
        assert str(trail["cipher"]) == "speck_p8_k16_o8_r2"
        assert trail["total_weight"] == 1.0
        assert int(trail["components_values"][INPUT_PLAINTEXT]["value"], base=16) > 0
        assert int(trail["components_values"][INPUT_KEY]["value"], base=16) == 0
        assert int(trail["components_values"]["modadd_0_1"]["value"], base=16) >= 0
        assert trail["components_values"]["modadd_0_1"]["weight"] >= 0.0
        assert int(trail["components_values"]["intermediate_output_0_6"]["value"], base=16) >= 0
        assert trail["components_values"]["intermediate_output_0_6"]["weight"] == 0


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trails = milp.find_all_xor_differential_trails_with_weight_at_most(0, 1)
    assert len(trails) == 7
    for trail in trails:
        assert 0.0 <= trail["total_weight"] <= 1.0


def test_find_lowest_weight_xor_differential_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trail = milp.find_lowest_weight_xor_differential_trail()
    assert trail["total_weight"] == 1.0

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck, n_window_heuristic=3)
    trail = milp.find_lowest_weight_xor_differential_trail()
    assert trail["total_weight"] == 1.0

    present = PresentBlockCipher(number_of_rounds=2)
    milp = MilpXorDifferentialModel(present)
    trail = milp.find_lowest_weight_xor_differential_trail()
    assert trail["total_weight"] == 4.0


def test_find_one_xor_differential_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    trail = milp.find_one_xor_differential_trail()
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
    trail = milp.find_one_xor_differential_trail_with_fixed_weight(5)
    assert trail["total_weight"] == 5.0

    tea = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
    milp = MilpXorDifferentialModel(tea)
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(32), bit_values=[0] * 32
    )
    round_0_output = set_fixed_variables(
        "intermediate_output_0_15", "equal", list(range(16)), integer_to_bit_list(0x0084, 16, "big")
    )
    cipher_output = set_fixed_variables(
        "cipher_output_1_16", "equal", list(range(16)), integer_to_bit_list(0x404A, 16, "big")
    )
    trail = milp.find_one_xor_differential_trail_with_fixed_weight(
        15, fixed_values=[key, round_0_output, cipher_output]
    )
    assert trail["total_weight"] == 15.0
    #
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    round_0_output = set_fixed_variables(
        "intermediate_output_0_6", "equal", list(range(16)), integer_to_bit_list(0x10001000, 16, "big")
    )
    cipher_output = set_fixed_variables(
        "cipher_output_1_12", "equal", list(range(16)), integer_to_bit_list(0x70203020, 16, "big")
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="not_equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    trail = milp.find_one_xor_differential_trail_with_fixed_weight(5, fixed_values=[key, round_0_output, cipher_output])
    assert trail["total_weight"] == 5.0
