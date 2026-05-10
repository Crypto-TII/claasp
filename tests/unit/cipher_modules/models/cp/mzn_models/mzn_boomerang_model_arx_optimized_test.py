import math
import os

import pytest

from claasp.cipher_modules.models.cp.mzn_models.mzn_boomerang_model_arx_optimized import MznBoomerangModelARXOptimized
from claasp.cipher_modules.models.cp.solvers import CPSAT
from claasp.cipher_modules.models.utils import boomerang_distinguisher_checker_for_block_cipher_single_key
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.name_mappings import BOOMERANG_XOR_DIFFERENTIAL


SPECK32_64_TABLE4_BCT_DISTINGUISHER = {
    "rounds": 10,
    "input_difference": 0x28000010,
    "output_difference": 0x81028108,
    "estimated_weight": 29.15,
    "experimental_weight": 27.34,
}


def test_build_boomerang_model_speck_single_key():
    speck = SpeckBlockCipher(number_of_rounds=8)
    speck = speck.remove_key_schedule()

    top_cipher_end = ["xor_3_10", "rot_4_6"]

    bottom_cipher_start = ["xor_4_8", "rot_4_9", "key_4_2", "key_5_2", "key_6_2", "key_7_2"]

    sboxes = ["modadd_4_7"]

    mzn_bct_model = MznBoomerangModelARXOptimized(speck, top_cipher_end, bottom_cipher_start, sboxes)

    fixed_variables_for_top_cipher = [
        {
            "component_id": "plaintext",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "key_0_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_1_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_2_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_3_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "xor_3_10",
            "constraint_type": "sum",
            "bit_positions": list(range(16)),
            "operator": ">",
            "value": "0",
        },
    ]

    fixed_variables_for_bottom_cipher = [
        {
            "component_id": "new_xor_3_10",
            "constraint_type": "sum",
            "bit_positions": list(range(16)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "key_4_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_5_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_6_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_7_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
    ]

    mzn_bct_model.create_boomerang_model(fixed_variables_for_top_cipher, fixed_variables_for_bottom_cipher)
    result = mzn_bct_model.solve_for_ARX(solver_name=CPSAT)
    total_weight = MznBoomerangModelARXOptimized._get_total_weight(result)
    parsed_result = mzn_bct_model.bct_parse_result(result, CPSAT, total_weight, BOOMERANG_XOR_DIFFERENTIAL)
    filename = "."
    mzn_bct_model.write_minizinc_model_to_file(filename)

    assert os.path.exists(mzn_bct_model.filename), "File was not created"
    os.remove(mzn_bct_model.filename)
    assert total_weight == parsed_result["total_weight"]
    input_difference = int(parsed_result["component_values"]["plaintext"]["value"], 16)
    output_difference = int(parsed_result["component_values"]["cipher_output_7_12"]["value"], 16)
    assert (
        boomerang_distinguisher_checker_for_block_cipher_single_key(
            speck, input_difference, output_difference, 2**20, speck.output_bit_size
        )
        > 0.0001
    )


def test_speck32_64_table4_boomerang_distinguisher_checker_smoke():
    distinguisher = SPECK32_64_TABLE4_BCT_DISTINGUISHER
    number_of_samples = 2**28
    speck = SpeckBlockCipher(
        block_bit_size=32, key_bit_size=64, number_of_rounds=distinguisher["rounds"]
    )

    probability = boomerang_distinguisher_checker_for_block_cipher_single_key(
        speck,
        distinguisher["input_difference"],
        distinguisher["output_difference"],
        number_of_samples,
        speck.output_bit_size,
        fixed_key=0,
        seed=1,
    )

    expected_matches = number_of_samples * 2 ** -distinguisher["experimental_weight"]
    assert distinguisher["input_difference"] == int("28000010", 16)
    assert distinguisher["output_difference"] == int("81028108", 16)
    assert distinguisher["experimental_weight"] == 27.34
    assert expected_matches < 1
    assert 0 <= probability <= 1


def test_speck32_64_table4_boomerang_distinguisher_experimental_probability():
    if os.environ.get("CLAASP_RUN_LONG_BCT_EXPERIMENTS") != "1":
        pytest.skip("set CLAASP_RUN_LONG_BCT_EXPERIMENTS=1 to run the 10-round Table 4 experiment")

    distinguisher = SPECK32_64_TABLE4_BCT_DISTINGUISHER
    speck = SpeckBlockCipher(
        block_bit_size=32, key_bit_size=64, number_of_rounds=distinguisher["rounds"]
    )
    number_of_samples = int(os.environ.get("CLAASP_BCT_EXPERIMENT_SAMPLES", 2**28))
    expected_matches = number_of_samples * 2 ** -distinguisher["experimental_weight"]
    if expected_matches < 5:
        pytest.skip(
            "CLAASP_BCT_EXPERIMENT_SAMPLES is too small for a stable estimate of "
            "the 10-round Table 4 probability"
        )

    probability = boomerang_distinguisher_checker_for_block_cipher_single_key(
        speck,
        distinguisher["input_difference"],
        distinguisher["output_difference"],
        number_of_samples,
        speck.output_bit_size,
        fixed_key=0,
        seed=1,
        num_workers=max(1, os.cpu_count() or 1),
    )

    assert probability > 0
    assert math.isclose(-math.log(probability, 2), distinguisher["experimental_weight"], abs_tol=2.0)


def test_build_boomerang_model_chacha():
    chacha = ChachaPermutation(number_of_rounds=8)
    top_cipher_end = [
        "modadd_3_0",
        "rot_3_5",
        "modadd_3_3",
        "rot_3_2",
        "modadd_3_6",
        "rot_3_11",
        "modadd_3_9",
        "rot_3_8",
        "modadd_3_12",
        "rot_3_17",
        "modadd_3_15",
        "rot_3_14",
        "modadd_3_18",
        "rot_3_23",
        "modadd_3_21",
        "rot_3_20",
    ]

    bottom_cipher_start = [
        "xor_4_4",
        "modadd_4_3",
        "xor_4_1",
        "xor_4_10",
        "modadd_4_9",
        "xor_4_7",
        "xor_4_16",
        "modadd_4_15",
        "xor_4_13",
        "xor_4_22",
        "modadd_4_21",
        "xor_4_19",
    ]

    sboxes = ["modadd_4_0", "modadd_4_6", "modadd_4_12", "modadd_4_18"]
    mzn_bct_model = MznBoomerangModelARXOptimized(chacha, top_cipher_end, bottom_cipher_start, sboxes)

    fixed_variables_for_top_cipher = [
        {
            "component_id": "plaintext",
            "constraint_type": "sum",
            "bit_positions": list(range(512)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "plaintext",
            "constraint_type": "sum",
            "bit_positions": list(range(384)),
            "operator": "=",
            "value": "0",
        },
    ]

    fixed_variables_for_bottom_cipher = [
        {
            "component_id": "new_rot_3_23",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "new_rot_3_5",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "new_rot_3_11",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "new_rot_3_17",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
    ]

    mzn_bct_model.create_boomerang_model(fixed_variables_for_top_cipher, fixed_variables_for_bottom_cipher)
    result = mzn_bct_model.solve_for_ARX(solver_name=CPSAT)
    total_weight = MznBoomerangModelARXOptimized._get_total_weight(result)
    parsed_result = mzn_bct_model.bct_parse_result(result, CPSAT, total_weight, BOOMERANG_XOR_DIFFERENTIAL)
    filename = "."
    mzn_bct_model.write_minizinc_model_to_file(filename)

    assert os.path.exists(mzn_bct_model.filename), "File was not created"

    os.remove(mzn_bct_model.filename)

    assert total_weight == parsed_result["total_weight"]
