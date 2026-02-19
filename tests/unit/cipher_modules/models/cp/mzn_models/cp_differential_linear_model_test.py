import itertools
import math

from claasp.cipher_modules.models.cp.mzn_models.cp_differential_linear_model import MznDifferentialLinearModel
from claasp.cipher_modules.models.cp.solvers import CPSAT
from claasp.cipher_modules.models.utils import (
    differential_linear_checker_for_block_cipher_single_key,
    integer_to_bit_list,
    set_fixed_variables,
    truncated_differential_linear_checker_permutation,
    differential_truncated_checker_single_key
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation, ROUND_MODE_HALF
from claasp.name_mappings import INPUT_PLAINTEXT, SATISFIABLE


def _split_components(cipher, top_rounds_end, middle_rounds_end):
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []

    for round_number in range(top_rounds_end):
        top_part_components.append(cipher.get_components_in_round(round_number))
    for round_number in range(top_rounds_end, middle_rounds_end):
        middle_part_components.append(cipher.get_components_in_round(round_number))
    for round_number in range(middle_rounds_end, cipher.number_of_rounds):
        bottom_part_components.append(cipher.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    return {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }


def test_differential_linear_trail_with_fixed_weight_6_rounds_speck_cp():
    speck = SpeckBlockCipher(number_of_rounds=6)
    speck_3 = SpeckBlockCipher(number_of_rounds=3)
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2, 3):
        middle_part_components.append(speck.get_components_in_round(round_number))
    for round_number in range(3, 6):
        bottom_part_components.append(speck.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    def _component_bit_size(component_id):
        if component_id == INPUT_PLAINTEXT:
            return 32
        if component_id == "key":
            return 64
        return speck.get_component_from_id(component_id).output_bit_size

    def _value_to_bits(value, bit_size):
        if value.startswith("0x"):
            return integer_to_bit_list(int(value, 16), bit_size, "big")
        return [2 if bit == "?" else int(bit) for bit in value]

    def _fixed_from_value(component_id, value):
        bit_size = _component_bit_size(component_id)
        return set_fixed_variables(
            component_id=component_id,
            constraint_type="equal",
            bit_positions=range(bit_size),
            bit_values=_value_to_bits(value, bit_size),
        )

    expected_components_values = {
        "plaintext": "0x05020402",
        "key": "0x0000000000000000",
        "cipher_output_5_12": "0x00040004",
        "rot_0_0": "0x040a",
        "modadd_0_1": "0x0008",
        "xor_0_4": "0x1000",
        "intermediate_output_0_6": "0x00081000",
        "intermediate_output_1_12": "0x00004000",
        "rot_1_6": "0x1000",
        "xor_1_10": "0x4000",
        "modadd_2_7": "?100000000000000",
        "xor_2_10": "?100000000000001",
        "intermediate_output_2_12": "?100000000000000?100000000000001",
        "xor_4_10": "0x0001",
        "intermediate_output_4_12": "0x00000001",
        "xor_5_10": "0x0004",
    }

    fixed_values = []
    for component_id, value in expected_components_values.items():
        if component_id.endswith("_o"):
            fixed_values.append(_fixed_from_value(component_id[:-2], value))
        else:
            fixed_values.append(_fixed_from_value(component_id, value))

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    model = MznDifferentialLinearModel(
        speck,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    trail = model.find_one_differential_linear_trail_with_fixed_weight(
        weight=8,
        fixed_values=fixed_values,
        solver_name=CPSAT,
        num_of_processors=4,
        solve_external=True,
    )
    # create a new variable with the sum of the probability weights of the modadd components for the three first rounds
    probability_weight_rounds_0_2 = 0
    for component_id in ["modadd_0_1", "modadd_1_2", "modadd_1_7", "modadd_2_2", "modadd_2_7"]:
        probability_weight_rounds_0_2 += float(trail["components_values"][component_id]["weight"])   
    print(trail)

    assert trail["status"] == SATISFIABLE
    for component_id in middle_part_components:
        value = trail["components_values"][component_id]["value"]
        assert set(value).issubset({"0", "1", "2"})

    assert trail["components_values"]["rot_0_0"]["value"] == "0x040a"
    assert trail["components_values"]["modadd_0_1"]["value"] == "0x0008"
    assert trail["components_values"]["xor_0_4"]["value"] == "0x1000"
    assert trail["components_values"]["intermediate_output_0_6"]["value"] == "0x00081000"
    assert trail["components_values"]["intermediate_output_1_12"]["value"] == "0x00004000"
    assert trail["components_values"]["rot_1_6"]["value"] == "0x1000"
    assert trail["components_values"]["xor_1_10"]["value"] == "0x4000"
    assert trail["components_values"]["modadd_2_7"]["value"] == "2100000000000000"
    assert trail["components_values"]["xor_2_10"]["value"] == "2100000000000001"
    assert trail["components_values"]["intermediate_output_2_12"]["value"] == "21000000000000002100000000000001"
    assert trail["components_values"]["xor_4_10_o"]["value"] == "0x0001"
    assert trail["components_values"]["intermediate_output_4_12_o"]["value"] == "0x00000001"
    assert trail["components_values"]["xor_5_10_o"]["value"] == "0x0004"

    assert trail["components_values"]["modadd_0_1"]["weight"] > 0
    assert trail["components_values"]["modadd_1_7"]["weight"] >= 0
    assert trail["components_values"]["modadd_3_2_o"]["weight"] > 0
    assert trail["components_values"]["modadd_3_7_o"]["weight"] > 0

    plaintext_as_int = int(trail["components_values"][INPUT_PLAINTEXT]["value"], 16)
    intermediate_output_2_12 = trail["components_values"]["intermediate_output_2_12"]["value"]
    output_mask_as_int = bin(int(trail["components_values"]["cipher_output_5_12_o"]["value"], 16))[2:].zfill(32)
    probability_weight = differential_truncated_checker_single_key(
        speck_3,
        plaintext_as_int,
        intermediate_output_2_12,
        1<<11,
        32,
        0x011,
        64,
        seed=3
    )
    assert abs(probability_weight) < float(probability_weight_rounds_0_2)+1

    correlation = differential_linear_checker_for_block_cipher_single_key(
        speck,
        plaintext_as_int,
        output_mask_as_int,
        1<<13,
        32,
        64,
        0x102040810,
        seed=None
    )

    assert abs(math.log(abs(correlation), 2)) <=  float(trail["total_weight"]) + 1




def test_differential_linear_trail_with_fixed_weight_4_rounds_chacha_golden():
    chacha = ChachaPermutation(number_of_rounds=8, round_mode=ROUND_MODE_HALF)
    component_model_list = _split_components(chacha, top_rounds_end=2, middle_rounds_end=4)

    state_size = 512
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=list(range(state_size)),
        bit_values=(0,) * state_size,
    )
    modadd_4_0 = set_fixed_variables(
        component_id="modadd_4_0",
        constraint_type="not_equal",
        bit_positions=list(range(32)),
        bit_values=(0,) * 32,
    )

    model = MznDifferentialLinearModel(
        chacha,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    trail = model.find_one_differential_linear_trail_with_fixed_weight(
        weight=12,
        fixed_values=[plaintext, modadd_4_0],
        solver_name=CPSAT,
        num_of_processors=4,
        solve_external=True,
    )
    print(trail)
    assert trail["status"] == SATISFIABLE
    assert float(trail["total_weight"]) <= 12


def test_differential_linear_trail_with_fixed_weight_8_rounds_chacha_one_case():
    chacha = ChachaPermutation(number_of_rounds=8, round_mode=ROUND_MODE_HALF)
    component_model_list = _split_components(chacha, top_rounds_end=2, middle_rounds_end=3)

    state_size = 512
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(
            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000,
            state_size,
            "big",
        ),
    )

    intermediate_output_2_24_string = "0000000000000000000000000000000000000000000000000000000000000000001000000010000000000?10000000100000010000000000000000000000000000000000010000000000000000000000?100000000000100000000000000000000000100000000000100000000000100001000100010001000100010001000100000001000000010001000000010000000000000000000000000010000000000000000000000?1000000000001000000000000000100000001000000000001000000000000000000000000000000000000000?100000001000100000001000000000000000000000000001000000000000000000000011000000000001000000"
    intermediate_output_2_24_values = []
    for character in intermediate_output_2_24_string:
        if character == "?":
            intermediate_output_2_24_values.append(2)
        else:
            intermediate_output_2_24_values.append(int(character))

    intermediate_output_2_24 = set_fixed_variables(
        component_id="intermediate_output_2_24",
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=intermediate_output_2_24_values,
    )

    ciphertext = set_fixed_variables(
        component_id="cipher_output_7_24",
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(
            0x00000001000000000000000101010181000080800000000000000000000800800000100000000101000000010000000000000000000000010100000100000101,
            state_size,
            "big",
        ),
    )

    model = MznDifferentialLinearModel(
        chacha,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    trail = model.find_one_differential_linear_trail_with_fixed_weight(
        weight=60,
        fixed_values=[plaintext, ciphertext, intermediate_output_2_24],
        solver_name=CPSAT,
        num_of_processors=4,
        solve_external=True,
    )

    assert trail["status"] == SATISFIABLE
    assert float(trail["total_weight"]) <= 60


def test_diff_lin_chacha():
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000
    output_mask = 0x00010000000100010000000100030003000000800000008000000000000001800000000000000001000000010000000201000101010000000000010103000101
    input_difference_as_string = bin(input_difference)[2:].zfill(512)
    output_mask_as_string = bin(output_mask)[2:].zfill(512)
    number_of_samples = 2**13
    number_of_rounds = 6
    state_size = 512
    chacha = ChachaPermutation(number_of_rounds=number_of_rounds, round_mode=ROUND_MODE_HALF)

    correlation = truncated_differential_linear_checker_permutation(
        chacha,
        input_difference_as_string,
        output_mask_as_string,
        number_of_samples,
        state_size,
    )
    absolute_correlation = abs(correlation)

    assert abs(math.log(absolute_correlation, 2)) < 3


def test_diff_lin_chacha_8():
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000
    output_mask = 0x00000001000000000000000101010181000080800000000000000000000800800000100000000101000000010000000000000000000000010100000100000101
    output_mask_as_string = bin(output_mask)[2:].zfill(512)
    number_of_samples = 2**10
    number_of_rounds = 8
    state_size = 512
    input_difference_as_string = bin(input_difference)[2:].zfill(512)
    chacha = ChachaPermutation(number_of_rounds=number_of_rounds, round_mode=ROUND_MODE_HALF)

    correlation = truncated_differential_linear_checker_permutation(
        chacha,
        input_difference_as_string,
        output_mask_as_string,
        number_of_samples,
        state_size,
    )
    absolute_correlation = abs(correlation)

    assert abs(math.log(absolute_correlation, 2)) < 8
