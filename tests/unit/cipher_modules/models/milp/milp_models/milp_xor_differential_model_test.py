import pytest

from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT

PRESENT_SBOX = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]


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
    trails = milp.find_all_xor_differential_trails_with_weight_at_most(1, 0)
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


def test_sbox_modeling():
    present = PresentBlockCipher(number_of_rounds=2)
    assert MilpXorDifferentialModel(present).sbox_modeling == "espresso"
    assert MilpXorDifferentialModel(present, sbox_modeling="one_hot").sbox_modeling == "one_hot"


def test_sbox_modeling_invalid():
    present = PresentBlockCipher(number_of_rounds=2)
    with pytest.raises(ValueError):
        MilpXorDifferentialModel(present, sbox_modeling="onehot")


def test_milp_one_hot_xor_differential_probability_constraints():
    cipher = SboxCipher(bit_size=4, lookup_table=PRESENT_SBOX)
    milp = MilpModel(cipher, sbox_modeling="one_hot")
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_one_hot_xor_differential_probability_constraints(
        milp.binary_variable, milp.integer_variable, milp.non_linear_component_id
    )

    assert len(variables) == 8
    assert len(constraints) == 4 + 4 + 2


def test_find_lowest_weight_xor_differential_trail_one_hot_sbox():
    cipher = SboxCipher(bit_size=4, lookup_table=PRESENT_SBOX)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=range(4),
        bit_values=[0] * 4,
    )

    one_hot = MilpXorDifferentialModel(cipher, sbox_modeling="one_hot")
    trail_one_hot = one_hot.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext])

    espresso = MilpXorDifferentialModel(cipher, sbox_modeling="espresso")
    trail_espresso = espresso.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext])

    assert trail_one_hot["total_weight"] == 2.0
    assert trail_one_hot["total_weight"] == trail_espresso["total_weight"]
