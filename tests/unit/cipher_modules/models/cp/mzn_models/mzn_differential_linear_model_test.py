import itertools
import math
import pytest

from claasp.cipher_modules.models.cp.mzn_models.mzn_differential_linear_model import MznDifferentialLinearModel
from claasp.cipher_modules.models.cp.solvers import CPSAT
from claasp.cipher_modules.models.utils import (
    differential_linear_checker_for_block_cipher_single_key,
    integer_to_bit_list,
    set_fixed_variables,
    truncated_differential_linear_checker_permutation,
    differential_truncated_checker_single_key
)
from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation, ROUND_MODE_HALF
from claasp.name_mappings import INPUT_PLAINTEXT, SATISFIABLE, INPUT_KEY, INPUT_MESSAGE
from claasp.ciphers.mac.siphash_mac import SiphashMAC

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


@pytest.mark.parametrize(
    "cipher_cls,cipher_kwargs,top_rounds_end,middle_rounds_end",
    [
        (SpeckBlockCipher, {"number_of_rounds": 6}, 2, 2),
        (ChachaPermutation, {"number_of_rounds": 6, "round_mode": ROUND_MODE_HALF}, 2, 4),
    ],
    ids=["speck_6_rounds", "chacha_6_rounds"],
)
def test_get_truncated_xor_differential_components_in_border(
    cipher_cls, cipher_kwargs, top_rounds_end, middle_rounds_end
):
    cipher = cipher_cls(**cipher_kwargs)
    component_model_list = _split_components(cipher, top_rounds_end=top_rounds_end, middle_rounds_end=middle_rounds_end)
    model = MznDifferentialLinearModel(
        cipher,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    expected_border_components = set()
    middle_components = set(component_model_list["middle_part_components"])
    for bottom_component_id in component_model_list["bottom_part_components"]:
        bottom_component = cipher.get_component_from_id(bottom_component_id)
        for input_id in bottom_component.input_id_links:
            if input_id in middle_components:
                expected_border_components.add(input_id)

    assert set(model._get_truncated_xor_differential_components_in_border()) == expected_border_components


def test_parse_linear_bit_id_handles_valid_and_invalid_formats():
    speck = SpeckBlockCipher(number_of_rounds=6)
    component_model_list = _split_components(speck, top_rounds_end=2, middle_rounds_end=3)
    model = MznDifferentialLinearModel(
        speck,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    assert model._parse_linear_bit_id("xor_0_4_o[7]") == ("xor_0_4", "o", 7)
    assert model._parse_linear_bit_id("plaintext[3]") == ("plaintext", None, 3)

    with pytest.raises(ValueError, match="Invalid linear bit identifier"):
        model._parse_linear_bit_id("invalid_bit_id")


def test_normalize_middle_part_components_values_hex_and_unknown_bits():
    speck = SpeckBlockCipher(number_of_rounds=6)
    component_model_list = _split_components(speck, top_rounds_end=2, middle_rounds_end=3)
    model = MznDifferentialLinearModel(
        speck,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    # middle-part round for this split includes these components.
    solution = {
        "components_values": {
            "modadd_2_7": {"value": "0x0001"},
            "xor_2_10": {"value": "1?00?00000000001"},
            "modadd_0_1": {"value": "0x0008"},
        }
    }

    model._normalize_middle_part_components_values(solution)

    assert solution["components_values"]["modadd_2_7"]["value"] == "0000000000000001"
    assert solution["components_values"]["xor_2_10"]["value"] == "1200200000000001"
    # Non-middle components are not touched.
    assert solution["components_values"]["modadd_0_1"]["value"] == "0x0008"


def test_component_and_probability_values_example_prints():
    speck = SpeckBlockCipher(number_of_rounds=6)
    component_model_list = _split_components(speck, top_rounds_end=2, middle_rounds_end=3)
    model = MznDifferentialLinearModel(
        speck,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    model.build_xor_differential_linear_model(weight=0, fixed_variables=[])

    print("component_and_probability:", model.component_and_probability)
    print("component_and_probability.values():", list(model.component_and_probability.values()))

    assert model.component_and_probability


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
        weight=10,
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




def test_differential_linear_trail_6_rounds_ballet_cp_case():
    ballet = BalletBlockCipher(number_of_rounds=6)
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2, 3):
        middle_part_components.append(ballet.get_components_in_round(round_number))
    for round_number in range(3, 6):
        bottom_part_components.append(ballet.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]
    cipher_output_component_id = ballet.get_all_components_ids()[-1]

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    model = MznDifferentialLinearModel(
        ballet,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    plaintext_difference = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(ballet.block_bit_size),
        bit_values=(0,) * ballet.block_bit_size
    )
    key_difference = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(ballet.key_bit_size),
        bit_values=(0,) * ballet.key_bit_size
    )
    ciphertext_output_mask = set_fixed_variables(
        component_id=cipher_output_component_id,
        constraint_type='not_equal',
        bit_positions=range(ballet.block_bit_size),
        bit_values=(0,) * ballet.block_bit_size,
    )

    solutions = model.find_lowest_weight_xor_differential_linear_trail(
        fixed_values=[key_difference, plaintext_difference, ciphertext_output_mask],
        solver_name=CPSAT,
        num_of_processors=4,
        solve_external=True,
    )

    if isinstance(solutions, list):
        trail = min(solutions, key=lambda s: float(s["total_weight"]))
    else:
        trail = solutions
    print(trail)
    assert trail["status"] == SATISFIABLE

    import math
    from claasp.cipher_modules.models.utils import differential_linear_checker_for_block_cipher_single_key

    input_difference_str = trail["components_values"]["plaintext"]["value"]
    cipher_output_key = next(k for k in trail["components_values"] if k.startswith("cipher_output_") and k.endswith("_o"))
    output_mask_str = trail["components_values"][cipher_output_key]["value"]
    print("Input difference:", input_difference_str)
    print("Output mask:", output_mask_str)
    print("Output component:", cipher_output_key)

    input_difference = int(input_difference_str, 16)
    output_mask = bin(int(output_mask_str, 16))[2:].zfill(ballet.block_bit_size)
    fixed_key = int(trail["components_values"]["key"]["value"], 16)

    corr = differential_linear_checker_for_block_cipher_single_key(
        ballet,
        input_difference,
        output_mask,
        1 << 14,
        ballet.block_bit_size,
        ballet.key_bit_size,
        fixed_key,
        seed=42
    )

    abs_corr = abs(corr)
    print("Total Differential-Linear Correlation |log2|:", abs(math.log(abs_corr, 2)) if abs_corr > 0 else float("inf"))



def test_differential_linear_trail_6_rounds_speck_cp_case_2():
    speck = SpeckBlockCipher(number_of_rounds=6)
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

    fixed_components_values = {
        "cipher_output_5_12_o": "0x00040004",
        "constant_1_0": "0x0000",
        "constant_2_0": "0000000000000000",
        "constant_3_0_o": "0x0080",
        "constant_4_0_o": "0x0001",
        "constant_5_0_o": "0x0000",
        "intermediate_output_0_5": "0x0000",
        "intermediate_output_0_6": "0x00008000",
        "intermediate_output_1_11": "0x0000",
        "intermediate_output_1_12": "0x80008002",
        "intermediate_output_2_11": "0000000000000000",
        "intermediate_output_2_12": "21111111000000102111111100001000",
        "intermediate_output_3_11_i": "0x4001",
        "intermediate_output_3_11_o": "0x4001",
        "intermediate_output_3_12_i": "0x00804001",
        "intermediate_output_3_12_o": "0x00804001",
        "intermediate_output_4_11_i": "0x0000",
        "intermediate_output_4_11_o": "0x0000",
        "intermediate_output_4_12_i": "0x00000001",
        "intermediate_output_4_12_o": "0x00000001",
        "intermediate_output_5_11_i": "0x0000",
        "intermediate_output_5_11_o": "0x0000",
        "key": "0x0000000000000000",
        "modadd_0_1": "0x0000",
        "modadd_1_2": "0x0000",
        "modadd_1_7": "0x8000",
        "modadd_2_2": "0000000000000000",
        "modadd_2_7": "2111111100000010",
        "modadd_3_2_i": "0x008000c0",
        "modadd_3_2_o": "0x0080",
        "modadd_3_7_i": "0x408160c1",
        "modadd_3_7_o": "0x4081",
        "modadd_4_2_i": "0x00010001",
        "modadd_4_2_o": "0x0001",
        "modadd_4_7_i": "0x00010001",
        "modadd_4_7_o": "0x0001",
        "modadd_5_2_i": "0x00000000",
        "modadd_5_2_o": "0x0000",
        "modadd_5_7_i": "0x00000000",
        "modadd_5_7_o": "0x0000",
        "plaintext": "0x00102000",
        "rot_0_0": "0x2000",
        "rot_0_3": "0x8000",
        "rot_1_1": "0x0000",
        "rot_1_4": "0x0000",
        "rot_1_6": "0x0000",
        "rot_1_9": "0x0002",
        "rot_2_1": "0000000000000000",
        "rot_2_4": "0000000000000000",
        "rot_2_6": "0000000100000000",
        "rot_2_9": "0000000000001010",
        "rot_3_1_i": "0x4000",
        "rot_3_1_o": "0x0080",
        "rot_3_4_i": "0x0020",
        "rot_3_4_o": "0x0080",
        "rot_3_6_i": "0x40a0",
        "rot_3_6_o": "0x4081",
        "rot_3_9_i": "0x5000",
        "rot_3_9_o": "0x4001",
        "rot_4_1_i": "0x0080",
        "rot_4_1_o": "0x0001",
        "rot_4_4_i": "0x4000",
        "rot_4_4_o": "0x0001",
        "rot_4_6_i": "0x0080",
        "rot_4_6_o": "0x0001",
        "rot_4_9_i": "0x4000",
        "rot_4_9_o": "0x0001",
        "rot_5_1_i": "0x0000",
        "rot_5_1_o": "0x0000",
        "rot_5_4_i": "0x0000",
        "rot_5_4_o": "0x0000",
        "rot_5_6_i": "0x0000",
        "rot_5_6_o": "0x0000",
        "rot_5_9_i": "0x0001",
        "rot_5_9_o": "0x0004",
        "xor_0_2": "0x0000",
        "xor_0_4": "0x8000",
        "xor_1_10": "0x8002",
        "xor_1_3": "0x0000",
        "xor_1_5": "0x0000",
        "xor_1_8": "0x8000",
        "xor_2_10": "2111111100001000",
        "xor_2_3": "0000000000000000",
        "xor_2_5": "0000000000000000",
        "xor_2_8": "2111111100000010",
        "xor_3_10_i": "0x40014001",
        "xor_3_10_o": "0x4001",
        "xor_3_3_i": "0x00800080",
        "xor_3_3_o": "0x0080",
        "xor_3_5_i": "0x00800080",
        "xor_3_5_o": "0x0080",
        "xor_3_8_i": "0x40814081",
        "xor_3_8_o": "0x4081",
        "xor_4_10_i": "0x00010001",
        "xor_4_10_o": "0x0001",
        "xor_4_3_i": "0x00010001",
        "xor_4_3_o": "0x0001",
        "xor_4_5_i": "0x00010001",
        "xor_4_5_o": "0x0001",
        "xor_4_8_i": "0x00010001",
        "xor_4_8_o": "0x0001",
        "xor_5_10_i": "0x00040004",
        "xor_5_10_o": "0x0004",
        "xor_5_3_i": "0x00000000",
        "xor_5_3_o": "0x0000",
        "xor_5_5_i": "0x00000000",
        "xor_5_5_o": "0x0000",
        "xor_5_8_i": "0x00000000",
        "xor_5_8_o": "0x0000",
    }

    fixed_values = []
    seen_component_ids = set()
    for component_id, value in fixed_components_values.items():
        if component_id.endswith("_i"):
            continue
        normalized_component_id = component_id[:-2] if component_id.endswith("_o") else component_id
        if normalized_component_id in seen_component_ids:
            continue
        seen_component_ids.add(normalized_component_id)
        fixed_values.append(_fixed_from_value(normalized_component_id, value))

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    model = MznDifferentialLinearModel(
        speck,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    trail = model.find_lowest_weight_xor_differential_linear_trail(
        fixed_values=fixed_values,
        solver_name=CPSAT,
        num_of_processors=4,
        solve_external=True,
    )

    if isinstance(trail, list):
        trail = min(trail, key=lambda s: float(s["total_weight"]))

    assert trail["status"] == SATISFIABLE

    for component_id, expected_value in fixed_components_values.items():
        if component_id.endswith("_i"):
            continue
        assert trail["components_values"][component_id]["value"] == expected_value

    
    assert math.isclose(float(trail["total_weight"]), 14.9943534369, rel_tol=1e-6, abs_tol=1e-6)


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
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(2, 4):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(4, 8):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    state_size = 512
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(
            0x80000000800000000000000000000000800000000000000000000000000000008080000080000000000000000000000000000080800080000000000000000000,
            state_size,
            "big",
        ),
    )

    ciphertext = set_fixed_variables(
        component_id="cipher_output_7_24",
        constraint_type="equal",
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(
            0x0000000100000000000000010000000004000000000800800000000000000000000000010008008000001000000000000000000000000101000000C000000001,
            state_size,
            "big",
        ),
    )

    component_model_list = {
        "middle_part_components": middle_part_components,
        "bottom_part_components": bottom_part_components,
    }

    model = MznDifferentialLinearModel(
        chacha,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
    )

    trail = model.find_one_differential_linear_trail_with_fixed_weight(
        weight=3,
        fixed_values=[plaintext, ciphertext],
        solver_name=CPSAT,
        num_of_processors=4,
        solve_external=True,
    )

    assert trail["status"] == SATISFIABLE
    assert float(trail["total_weight"]) == 3
    assert trail["components_values"][INPUT_PLAINTEXT]["value"] == (
        "0x80000000800000000000000000000000800000000000000000000000000000008080000080000000000000000000000000000080800080000000000000000000"
    )
    cipher_output_key = "cipher_output_7_24"
    if cipher_output_key not in trail["components_values"]:
        cipher_output_key = "cipher_output_7_24_o"

    assert trail["components_values"][cipher_output_key]["value"] == (
        "0x0000000100000000000000010000000004000000000800800000000000000000000000010008008000001000000000000000000000000101000000c000000001"
    )
    assert float(trail["components_values"][cipher_output_key]["weight"]) == 0

    input_difference_as_string = bin(int(trail["components_values"][INPUT_PLAINTEXT]["value"], 16))[2:].zfill(state_size)
    output_mask_as_string = bin(int(trail["components_values"][cipher_output_key]["value"], 16))[2:].zfill(state_size)
    correlation = truncated_differential_linear_checker_permutation(
        chacha,
        input_difference_as_string,
        output_mask_as_string,
        2**13,
        state_size,
        seed=42
    )
    absolute_correlation = abs(correlation)
    assert absolute_correlation > 0
    print(abs(math.log(absolute_correlation, 2)))
    assert abs(math.log(absolute_correlation, 2)) <= float(trail["total_weight"]) + 1


@pytest.mark.parametrize(
    "input_difference,output_mask,number_of_samples,number_of_rounds,threshold",
    [
        (
            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000,
            0x00010000000100010000000100030003000000800000008000000000000001800000000000000001000000010000000201000101010000000000010103000101,
            2**13,
            6,
            3,
        ),
        (
            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000,
            0x00000001000000000000000101010181000080800000000000000000000800800000100000000101000000010000000000000000000000010100000100000101,
            2**10,
            8,
            8,
        ),
    ],
    ids=["chacha_6_rounds", "chacha_8_rounds"],
)
def test_diff_lin_chacha_permutation_cases(
    input_difference, output_mask, number_of_samples, number_of_rounds, threshold
):
    state_size = 512
    input_difference_as_string = bin(input_difference)[2:].zfill(state_size)
    output_mask_as_string = bin(output_mask)[2:].zfill(state_size)
    chacha = ChachaPermutation(number_of_rounds=number_of_rounds, round_mode=ROUND_MODE_HALF)

    correlation = truncated_differential_linear_checker_permutation(
        chacha,
        input_difference_as_string,
        output_mask_as_string,
        number_of_samples,
        state_size,
    )
    absolute_correlation = abs(correlation)

    assert abs(math.log(absolute_correlation, 2)) < threshold


def test_lowest_semi_deterministic_differential_linear_trail_siphash():


    siphash = SiphashMAC(message_byte_size=15, compression_rounds=2, finalization_rounds=2)
    siphash.print()

    # Siphash has 7 rounds (0..6). With no top part, split as 0/5/2.
    first_cryptanalytic_round = 0
    top_len, middle_len, bottom_len = 0, 5, 2

    top_rounds = range(first_cryptanalytic_round, first_cryptanalytic_round + top_len)
    middle_rounds = range(first_cryptanalytic_round + top_len, first_cryptanalytic_round + top_len + middle_len)
    bottom_rounds = range(first_cryptanalytic_round + top_len + middle_len, first_cryptanalytic_round + top_len + middle_len + bottom_len)

    top_part_components = []
    for round_number in top_rounds:
        top_part_components += siphash.get_components_in_round(round_number)

    middle_part_components = []
    for round_number in middle_rounds:
        middle_part_components += siphash.get_components_in_round(round_number)

    bottom_part_components = []
    for round_number in bottom_rounds:
        bottom_part_components += siphash.get_components_in_round(round_number)

    top_part_component_ids = [component.id for component in top_part_components]
    middle_part_component_ids = [component.id for component in middle_part_components]
    bottom_part_component_ids = [component.id for component in bottom_part_components]

    print("Top rounds:", list(top_rounds))
    print("Middle rounds:", list(middle_rounds))
    print("Bottom rounds:", list(bottom_rounds))
    print()
    print("Top components count:", len(top_part_component_ids))
    print("Middle components count:", len(middle_part_component_ids))
    print("Bottom components count:", len(bottom_part_component_ids))

    component_model_list = {
        "middle_part_components": middle_part_component_ids,
        "bottom_part_components": bottom_part_component_ids
    }

    mzn_differential_linear_model = MznDifferentialLinearModel(
        siphash,
        component_model_list,
        middle_part_model="cp_semi_deterministic_truncated_xor_differential_constraints",
        standard_differential_part=False,
    )

    key_size = siphash.inputs_bit_size[0]
    message_size = siphash.inputs_bit_size[1]

    key_difference = set_fixed_variables(
        component_id=INPUT_KEY,
        constraint_type="equal",
        bit_positions=range(key_size),
        bit_values=(0,) * key_size
    )

    message_difference = set_fixed_variables(
        component_id=INPUT_MESSAGE,
        constraint_type="not_equal",
        bit_positions=range(message_size),
        bit_values=(0,) * message_size
    )

    cipher_output_component_id = next(c.id for c in siphash.get_all_components() if c.id.startswith("cipher_output_"))
    output_mask = set_fixed_variables(
        component_id=cipher_output_component_id,
        constraint_type="not_equal",
        bit_positions=range(siphash.output_bit_size),
        bit_values=(0,) * siphash.output_bit_size
    )

    fixed_values = [key_difference, message_difference, output_mask]
    print("Output component used:", cipher_output_component_id)

    solutions = mzn_differential_linear_model.find_lowest_weight_xor_differential_linear_trail(
        fixed_values=fixed_values,
        solver_name=CPSAT,
        solve_external=True,
        num_of_processors=4,
        timelimit=60000,
        intermediate_solutions=True
    )

    if isinstance(solutions, list):
        trail = min(solutions, key=lambda s: float(s["total_weight"]))
    else:
        trail = solutions

    print("Status:", trail["status"])
    print("Total weight:", trail["total_weight"])
    assert trail["status"] == SATISFIABLE
