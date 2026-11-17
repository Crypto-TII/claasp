import math
from os import path, remove

import pytest

from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
from claasp.cipher_modules.models.sat.solvers import CRYPTOMINISAT_EXT, KISSAT_EXT
from claasp.cipher_modules.models.utils import linear_checker_for_block_cipher_single_key, set_fixed_variables
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import SATISFIABLE


def test_branch_xor_linear_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorLinearModel(speck)

    constraints = SatXorLinearModel.branch_xor_linear_constraints(sat.bit_bindings)

    assert constraints[0] == "-plaintext_0_o rot_0_0_0_i"
    assert constraints[1] == "plaintext_0_o -rot_0_0_0_i"
    assert constraints[2] == "-plaintext_1_o rot_0_0_1_i"
    assert constraints[-3] == "xor_2_10_14_o -cipher_output_2_12_30_i"
    assert constraints[-2] == "-xor_2_10_15_o cipher_output_2_12_31_i"
    assert constraints[-1] == "xor_2_10_15_o -cipher_output_2_12_31_i"


def test_find_all_xor_linear_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
    sat = SatXorLinearModel(speck)
    key = set_fixed_variables("key", "not_equal", list(range(16)), [0] * 16)
    trails = sat.find_all_xor_linear_trails_with_weight_at_most(0, 3, fixed_values=[key])

    assert len(trails) == 73


def test_find_lowest_weight_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    sat = SatXorLinearModel(speck)
    trail = sat.find_lowest_weight_xor_linear_trail()

    assert trail["total_weight"] == 3.0
    input_mask = bin(int(trail["components_values"]["plaintext"]["value"], 16))[2:].zfill(32)
    output_mask = bin(int(trail["components_values"]["cipher_output_3_12_o"]["value"], 16))[2:].zfill(32)

    corr = linear_checker_for_block_cipher_single_key(
        speck,
        input_mask,
        output_mask,
        number_of_samples=2**14,
        block_size=32,
        key_size=64,
        fixed_key=0,
        seed=None,
    )
    empirical_weight = abs(math.log(abs(corr), 2)) if corr != 0 else float("inf")
    theoretical_weight = float(trail["total_weight"])
    assert math.isfinite(empirical_weight)
    # With only 4096 samples this is noisy; enforce a soft upper bound vs. theory.
    assert empirical_weight <= theoretical_weight + 2.0


def test_find_lowest_weight_xor_linear_trail_with_log(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    sat = SatXorLinearModel(speck)
    start_weight = 1
    lowest_weight = 3
    log_file_name = f"{speck.id}__sat_find_lowest_weight_xor_linear_trail_from_below__{CRYPTOMINISAT_EXT}solver.log"
    try:
        trail = sat.find_lowest_weight_xor_linear_trail(start_weight=start_weight, log=True)
        with open(log_file_name) as f:
            log_content = f.read()
    finally:
        if path.exists(log_file_name):
            remove(log_file_name)

    assert trail["status"] == SATISFIABLE
    assert trail["total_weight"] == lowest_weight
    log_lines = log_content.splitlines()

    # every weight from start_weight to lowest_weight - 1, and only those, is reported as UNSATISFIABLE, in order
    lower_bound_lines = [line for line in log_lines if " has no " in line]
    assert len(lower_bound_lines) == lowest_weight - start_weight
    for weight, line in enumerate(lower_bound_lines, start=start_weight):
        assert line.endswith(f" {speck.id} has no xor_linear trail of weight <= {weight}")
    status_lines = [line for line in log_lines if " (status: " in line]
    assert len(status_lines) == lowest_weight - start_weight + 1
    for weight, line in enumerate(status_lines[:-1], start=start_weight):
        assert f" {CRYPTOMINISAT_EXT} terminated the search for weight {weight} in " in line
        assert line.endswith(" (status: UNSATISFIABLE)")
    # a time estimate follows every lower bound except the first one
    assert log_content.count("is expected to terminate in") == lowest_weight - start_weight - 1

    # the search for lowest_weight is reported as SATISFIABLE, with the weight of the returned trail
    assert f" {CRYPTOMINISAT_EXT} terminated the search for weight {lowest_weight} in " in status_lines[-1]
    assert status_lines[-1].endswith(" (status: SATISFIABLE)")
    trail_lines = [line for line in log_lines if " has a " in line]
    assert len(trail_lines) == 1
    assert trail_lines[0].endswith(f" {speck.id} has a xor_linear trail of weight {trail['total_weight']}")

    # the log ends with the returned trail
    assert f"'components_values': {trail['components_values']!r}" in log_lines[-1]
    assert f"'total_weight': {trail['total_weight']!r}" in log_lines[-1]


def test_find_one_xor_linear_trail():
    speck = SpeckBlockCipher(number_of_rounds=4)
    sat = SatXorLinearModel(speck)
    trail = sat.find_one_xor_linear_trail()

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r4"
    assert trail["model_type"] == "xor_linear"
    assert trail["status"] == "SATISFIABLE"


def test_find_one_xor_linear_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorLinearModel(speck)
    result = sat.find_one_xor_linear_trail(lower_bound=7, upper_bound=7)

    assert result["total_weight"] == 7.0


def test_fix_variables_value_xor_linear_constraints():
    fixed_variables = [
        {
            "component_id": "plaintext",
            "constraint_type": "equal",
            "bit_positions": [0, 1, 2, 3],
            "bit_values": [1, 0, 1, 1],
        },
        {
            "component_id": "ciphertext",
            "constraint_type": "not_equal",
            "bit_positions": [0, 1, 2, 3],
            "bit_values": [1, 1, 1, 0],
        },
    ]
    constraints = SatXorLinearModel.fix_variables_value_xor_linear_constraints(fixed_variables)

    assert constraints == [
        "plaintext_0_o",
        "-plaintext_1_o",
        "plaintext_2_o",
        "plaintext_3_o",
        "-ciphertext_0_o -ciphertext_1_o -ciphertext_2_o ciphertext_3_o",
    ]


# Goal: the search with Matsui bounds finds the same optimum as the plain search and only adds weight constraints
# to the unchanged propagation model.
@pytest.mark.parametrize(
    "cipher, matsui_bounds, lowest_weight",
    [
        (PresentBlockCipher(number_of_rounds=4), [1, 2, 4], 6),
        (SpeckBlockCipher(number_of_rounds=7), [0, 0, 1, 3, 5, 7], 9),
        (SimonBlockCipher(number_of_rounds=6), [0, 1, 2, 3, 4], 6),
    ],
)
def test_find_lowest_weight_xor_linear_trail_with_matsui_bounds(cipher, matsui_bounds, lowest_weight):
    plain = SatXorLinearModel(cipher).find_lowest_weight_xor_linear_trail(solver_name=KISSAT_EXT)
    sat = SatXorLinearModel(cipher)
    trail = sat.find_lowest_weight_xor_linear_trail_with_matsui_bounds(matsui_bounds, solver_name=KISSAT_EXT)
    assert plain["total_weight"] == trail["total_weight"] == lowest_weight
    assert trail["status"] == SATISFIABLE
    assert trail["test_name"] == "find_lowest_weight_xor_linear_trail_with_matsui_bounds"

    # the model is the unchanged propagation model plus the new weight constraints only
    reference = SatXorLinearModel(cipher)
    reference.build_xor_linear_trail_model()
    number_of_propagation_constraints = len(reference.model_constraints)
    assert sat.model_constraints[:number_of_propagation_constraints] == reference.model_constraints
    new_variables = sat._variables_list[len(reference._variables_list) :]
    assert sat._variables_list[: len(reference._variables_list)] == reference._variables_list
    assert new_variables
    assert all(variable.startswith("matsui_") for variable in new_variables)


# Goal: the search starting from a given weight still finds the optimum and writes the solver log file.
def test_find_lowest_weight_xor_linear_trail_with_matsui_bounds_start_weight_and_log(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    speck = SpeckBlockCipher(number_of_rounds=7)
    sat = SatXorLinearModel(speck)
    log_file_name = f"{speck.id}__sat_find_lowest_weight_xor_linear_trail_with_matsui_bounds__{KISSAT_EXT}solver.log"
    try:
        trail = sat.find_lowest_weight_xor_linear_trail_with_matsui_bounds(
            [0, 0, 1, 3, 5, 7], solver_name=KISSAT_EXT, start_weight=8, log=True
        )
        assert trail["total_weight"] == 9
        assert path.exists(log_file_name)
    finally:
        if path.exists(log_file_name):
            remove(log_file_name)


# Goal: the weight variables of the linear model are correctly grouped by round, also when the key schedule is
# removed, and a mismatch with the model raises an error.
def test_hw_variables_by_round_xor_linear():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorLinearModel(speck)
    sat.build_xor_linear_trail_model()
    hw_variables_by_round = sat._hw_variables_by_round()
    assert [len(round_variables) for round_variables in hw_variables_by_round] == [16, 16, 16]
    assert all(variable.startswith("hw_modadd_0_") for variable in hw_variables_by_round[0])
    assert all(variable.startswith("hw_modadd_2_") for variable in hw_variables_by_round[2])
    # the model must contain the weight variables of its components
    sat._variables_list.append("hw_extra")
    with pytest.raises(ValueError, match="do not match"):
        sat._hw_variables_by_round()


# Goal: the documented round-by-round loop, feeding each optimum as the next Matsui bound, gives the lowest weights
# found by the classical search.
@pytest.mark.parametrize(
    "cipher_class, lowest_weights",
    [
        (PresentBlockCipher, [1, 2, 4, 6, 8, 10]),
        (SpeckBlockCipher, [0, 0, 1, 3, 5, 7, 9]),
    ],
)
def test_find_lowest_weight_xor_linear_trail_with_matsui_bounds_round_by_round(cipher_class, lowest_weights):
    matsui_bounds = []
    for number_of_rounds in range(1, len(lowest_weights) + 1):
        sat = SatXorLinearModel(cipher_class(number_of_rounds=number_of_rounds))
        trail = sat.find_lowest_weight_xor_linear_trail_with_matsui_bounds(matsui_bounds, solver_name=KISSAT_EXT)
        matsui_bounds.append(int(trail["total_weight"]))
    assert matsui_bounds == lowest_weights
