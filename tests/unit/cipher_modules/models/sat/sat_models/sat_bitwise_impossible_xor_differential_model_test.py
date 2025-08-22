from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_impossible_xor_differential_model import (
    SatBitwiseImpossibleXorDifferentialModel,
)
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT


SIMON_INCOMPATIBLE_ROUND_OUTPUT = "????????00?????0???????0????????"


def test_build_bitwise_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=2)
    sat = SatBitwiseImpossibleXorDifferentialModel(speck)
    sat._forward_cipher = speck.get_partial_cipher(0, 1, keep_key_schedule=True)
    backward_cipher = sat._cipher.cipher_partial_inverse(1, 1, keep_key_schedule=False)
    sat._backward_cipher = backward_cipher.add_suffix_to_components(
        "_backward", [backward_cipher.get_all_components_ids()[-1]]
    )
    sat.build_bitwise_impossible_xor_differential_trail_model()
    constraints = sat.model_constraints

    assert len(constraints) == 2625
    assert constraints[0] == "rot_0_0_0_0 -plaintext_9_0"
    assert constraints[1] == "plaintext_9_0 -rot_0_0_0_0"
    assert constraints[-2] == "intermediate_output_0_6_backward_31_1 -rot_1_9_15_1"
    assert constraints[-1] == "rot_1_9_15_1 -intermediate_output_0_6_backward_31_1"


def test_find_one_bitwise_impossible_xor_differential_trail_model():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
    sat = SatBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="equal", bit_positions=range(32), bit_values=(0,) * 31 + (1,)
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    ciphertext = set_fixed_variables(
        component_id="cipher_output_10_13",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[0] * 6 + [2, 0, 2] + [0] * 23,
    )
    trail = sat.find_one_bitwise_impossible_xor_differential_trail(6, fixed_values=[plaintext, key, ciphertext])
    assert trail["status"] == "SATISFIABLE"
    assert trail["components_values"]["intermediate_output_5_12"]["value"] == "????????????????0??????1??????0?"
    assert trail["components_values"]["intermediate_output_5_12_backward"]["value"] == SIMON_INCOMPATIBLE_ROUND_OUTPUT


# fmt: off
def test_find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components():
    ascon = AsconSboxSigmaPermutation(number_of_rounds=5)
    sat = SatBitwiseImpossibleXorDifferentialModel(ascon)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(320),
        bit_values=(1,) + (0,) * 191 + (1,) + (0,) * 63 + (1,) + (0,) * 63
    )
    P1 = set_fixed_variables(
        component_id="intermediate_output_0_71",
        constraint_type="equal",
        bit_positions=range(320),
        bit_values=(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0,
            2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ),
    )
    P2 = set_fixed_variables(
        component_id="intermediate_output_1_71",
        constraint_type="equal",
        bit_positions=range(320),
        bit_values=(
            2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0,
            0, 0, 2, 0, 2, 0, 2, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0,
            2, 2, 0, 2, 0, 0, 2, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 2, 2, 0,
            2, 2, 2, 2, 0, 0, 2, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0,
            2, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 2, 0, 2, 2, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0,
            0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0,
            2, 0, 0, 0, 2, 0, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 0, 0,
        ),
    )
    P3 = set_fixed_variables(
        component_id="intermediate_output_2_71",
        constraint_type="equal",
        bit_positions=range(320),
        bit_values=(
            2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0,
            2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2,
            0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0,
            0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2,
            2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 0, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ),
    )
    P5 = set_fixed_variables(
        component_id="cipher_output_4_71",
        constraint_type="equal",
        bit_positions=range(320),
        bit_values=(0,) * 192 + (1,) + (0,) * 127
    )
    trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_chosen_incompatible_components(
        ["sbox_3_56"], fixed_values=[plaintext, P1, P2, P3, P5]
    )
    assert trail["status"] == "SATISFIABLE"
    assert trail["components_values"]["sbox_3_56"]["value"] == "00000"
    assert trail["components_values"]["sigma_3_69_backward"]["value"] == "1000101000101010101010000000001010001000000010101000001010000000"
# fmt: on


def test_find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
    sat = SatBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="equal", bit_positions=range(32), bit_values=(0,) * 31 + (1,)
    )
    key = set_fixed_variables(
        component_id="key", constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    key_backward = set_fixed_variables(
        component_id="key_backward", constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    ciphertext_backward = set_fixed_variables(
        component_id="cipher_output_10_13_backward",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0,) * 6 + (2, 0, 2) + (0,) * 23,
    )
    trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(
        fixed_values=[plaintext, key, key_backward, ciphertext_backward]
    )
    assert trail["status"] == "SATISFIABLE"
    assert trail["components_values"]["plaintext"]["value"] == "00000000000000000000000000000001"
    assert trail["components_values"]["intermediate_output_5_12_backward"]["value"] == SIMON_INCOMPATIBLE_ROUND_OUTPUT
    assert trail["components_values"]["cipher_output_10_13_backward"]["value"] == "000000?0?00000000000000000000000"

    trail = sat.find_one_bitwise_impossible_xor_differential_trail_with_fully_automatic_model(
        fixed_values=[plaintext, key, key_backward, ciphertext_backward], include_all_components=True
    )
    assert trail["status"] == "SATISFIABLE"
    assert trail["components_values"]["plaintext"]["value"] == "00000000000000000000000000000001"
    assert trail["components_values"]["intermediate_output_5_12_backward"]["value"] == SIMON_INCOMPATIBLE_ROUND_OUTPUT
    assert trail["components_values"]["cipher_output_10_13_backward"]["value"] == "000000?0?00000000000000000000000"
