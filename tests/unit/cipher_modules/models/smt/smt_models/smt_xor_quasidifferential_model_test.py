from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import (
    SmtXorQuasidifferentialModel,
)
from claasp.cipher_modules.models.smt.solvers import Z3_EXT
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.rectangle_block_cipher import RectangleBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT


def test_find_one_xor_quasidifferential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    smt = SmtXorQuasidifferentialModel(speck)
    solution = smt.find_one_xor_quasidifferential_trail()
    assert str(solution["cipher"]) == "speck_p32_k64_o32_r5"
    assert solution["solver_name"] == Z3_EXT
    assert int(solution["components_values"]["intermediate_output_4_11"]["value"], 16) >= 0
    assert solution["components_values"]["intermediate_output_4_11"]["weight"] == 0
    assert int(solution["components_values"]["cipher_output_4_12"]["value"], 16) >= 0
    assert solution["components_values"]["cipher_output_4_12"]["weight"] == 0
    assert "mask" in solution["components_values"]["cipher_output_4_12"]


def test_find_lowest_weight_xor_quasidifferential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    smt = SmtXorQuasidifferentialModel(speck)
    trail = smt.find_lowest_weight_xor_quasidifferential_trail()
    assert trail["total_weight"] == 9.0


def test_find_one_xor_quasidifferential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorQuasidifferentialModel(speck)
    result = smt.find_one_xor_quasidifferential_trail_with_fixed_weight(3)
    assert result["total_weight"] == 3.0


def test_find_one_xor_quasidifferential_trail_on_rectangle():
    rectangle = RectangleBlockCipher(number_of_rounds=1)
    smt = SmtXorQuasidifferentialModel(rectangle)
    solution = smt.find_one_xor_quasidifferential_trail()
    assert str(solution["cipher"]) == "rectangle_p64_k80_o64_r1"
    assert solution["solver_name"] == Z3_EXT
    assert solution["total_weight"] >= 0


def test_find_lowest_weight_xor_quasidifferential_trail_on_rectangle():
    rectangle = RectangleBlockCipher(number_of_rounds=1)
    smt = SmtXorQuasidifferentialModel(rectangle)
    plaintext = set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(64), (0,) * 64)
    trail = smt.find_lowest_weight_xor_quasidifferential_trail(fixed_values=[plaintext])
    assert trail["total_weight"] == 0.0


def test_find_one_xor_quasidifferential_trail_on_simon():
    simon = SimonBlockCipher(number_of_rounds=1)
    smt = SmtXorQuasidifferentialModel(simon)
    solution = smt.find_one_xor_quasidifferential_trail()
    assert str(solution["cipher"]) == "simon_p32_k64_o32_r1"
    assert solution["solver_name"] == Z3_EXT
    assert solution["components_values"]["and_0_4"]["weight"] == solution["total_weight"]


def test_compute_trail_sign():
    speck = SpeckBlockCipher(number_of_rounds=6)
    smt = SmtXorQuasidifferentialModel(speck)
    fixed_values = _speck_six_round_characteristic()
    trail = smt.find_one_xor_quasidifferential_trail_with_fixed_weight(13, fixed_values=fixed_values)
    assert trail["total_weight"] == 13.0
    assert smt.compute_trail_sign(trail) == 1


def test_estimate_fixed_key_probability():
    speck = SpeckBlockCipher(number_of_rounds=6)
    smt = SmtXorQuasidifferentialModel(speck)
    fixed_masks = [
        {"component_id": INPUT_PLAINTEXT, "bit_positions": range(32), "bit_values": [0] * 32},
        {"component_id": INPUT_KEY, "bit_positions": range(64), "bit_values": [0] * 64},
        {"component_id": "cipher_output_5_12", "bit_positions": range(32), "bit_values": [0] * 32},
    ]
    result = smt.estimate_fixed_key_probability(
        max_weight=13,
        min_weight=13,
        fixed_values=_speck_six_round_characteristic(),
        fixed_masks=fixed_masks,
    )
    assert result["num_trails"] == 1
    assert result["trails"][0]["sign"] == 1
    assert result["estimated_probability"] == 2.0**-13


def _speck_six_round_characteristic():
    differences = {
        INPUT_PLAINTEXT: 0x02110A04,
        "intermediate_output_0_6": 0x28000010,
        "intermediate_output_1_12": 0x00400000,
        "intermediate_output_2_12": 0x80008000,
        "intermediate_output_3_12": 0x81008102,
        "intermediate_output_4_12": 0x8000840A,
        "cipher_output_5_12": 0x850A9520,
    }
    fixed_values = [set_fixed_variables(INPUT_KEY, "equal", range(64), (0,) * 64)]
    for component_id, difference in differences.items():
        bit_values = [(difference >> (31 - i)) & 1 for i in range(32)]
        fixed_values.append(set_fixed_variables(component_id, "equal", range(32), bit_values))

    return fixed_values