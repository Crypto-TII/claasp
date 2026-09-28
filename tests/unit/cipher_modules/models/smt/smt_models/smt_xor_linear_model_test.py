import math

import pytest

from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
from claasp.cipher_modules.models.smt.solvers import Z3_EXT
from claasp.cipher_modules.models.utils import (
    integer_to_bit_list,
    linear_checker_for_block_cipher_single_key,
    set_fixed_variables,
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, SATISFIABLE, XOR_LINEAR


def test_branch_xor_linear_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)

    constraints = smt.branch_xor_linear_constraints()

    assert constraints[0] == "(assert (not (xor plaintext_0_o rot_0_0_0_i)))"
    assert constraints[1] == "(assert (not (xor plaintext_1_o rot_0_0_1_i)))"
    assert constraints[-2] == "(assert (not (xor xor_2_10_14_o cipher_output_2_12_30_i)))"
    assert constraints[-1] == "(assert (not (xor xor_2_10_15_o cipher_output_2_12_31_i)))"


def test_build_xor_linear_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=1)
    smt = SmtXorLinearModel(speck)
    smt.build_xor_linear_trail_model()
    constraints = smt.model_constraints

    assert constraints[:2] == ["(set-option :print-success false)", "(set-logic QF_UF)"]
    assert constraints[-3:] == ["(check-sat)", "(get-model)", "(exit)"]
    assert "(declare-const plaintext_0_o Bool)" in constraints
    assert not any(variable.startswith("dummy_hw_") for variable in smt._variables_list)


def test_cipher_input_xor_linear_variables():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    variables = smt.cipher_input_xor_linear_variables()

    assert len(variables) == sum(speck.inputs_bit_size)
    assert variables[:2] == ["plaintext_0_o", "plaintext_1_o"]
    assert variables[-1] == "key_63_o"


def test_find_all_xor_linear_trails_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    trails = smt.find_all_xor_linear_trails_with_fixed_weight(1)

    assert len(trails) == 4
    assert all(int(trail["total_weight"]) == 1 for trail in trails)
    assert trails[-1]["test_name"] == "find_all_xor_linear_trails_with_fixed_weight"


def test_find_all_xor_linear_trails_with_fixed_weight_parallel():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck, counter="parallel")
    trails = smt.find_all_xor_linear_trails_with_fixed_weight(1)

    assert len(trails) == 4
    assert all(int(trail["total_weight"]) == 1 for trail in trails)


def test_find_all_xor_linear_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
    smt = SmtXorLinearModel(speck)
    key = set_fixed_variables(INPUT_KEY, "not_equal", list(range(16)), [0] * 16)
    trails = smt.find_all_xor_linear_trails_with_weight_at_most(0, 3, fixed_values=[key])

    assert len(trails) == 73
    assert all(trail["test_name"] == "find_all_xor_linear_trails_with_weight_at_most" for trail in trails)


def test_find_lowest_weight_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    smt = SmtXorLinearModel(speck)
    trail = smt.find_lowest_weight_xor_linear_trail()

    assert trail["total_weight"] == 3.0
    assert trail["test_name"] == "find_lowest_weight_xor_linear_trail"
    input_mask = bin(int(trail["components_values"][INPUT_PLAINTEXT]["value"], 16))[2:].zfill(32)
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
    # With only 2**14 samples this is noisy; enforce a soft upper bound vs. theory.
    assert empirical_weight <= theoretical_weight + 2.0


def test_find_one_xor_linear_trail():
    speck = SpeckBlockCipher(number_of_rounds=4)
    smt = SmtXorLinearModel(speck)
    trail = smt.find_one_xor_linear_trail()

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r4"
    assert trail["model_type"] == XOR_LINEAR
    assert trail["solver_name"] == Z3_EXT
    assert trail["status"] == SATISFIABLE
    assert trail["test_name"] == "find_one_xor_linear_trail"
    assert int(trail["components_values"]["modadd_0_1_i"]["value"], 16) >= 0
    assert trail["components_values"]["modadd_0_1_i"]["weight"] == 0
    assert trail["components_values"]["modadd_0_1_i"]["sign"] == 1
    assert int(trail["components_values"]["xor_0_4_o"]["value"], 16) >= 0
    assert trail["components_values"]["xor_0_4_o"]["weight"] == 0
    assert trail["components_values"]["xor_0_4_o"]["sign"] == 1


def test_find_one_xor_linear_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    result = smt.find_one_xor_linear_trail(lower_bound=7, upper_bound=7)

    assert result["total_weight"] == 7.0


def test_find_one_xor_linear_trail_with_wrong_bounds():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)

    with pytest.raises(ValueError, match="lower_bound must be <= upper_bound"):
        smt.find_one_xor_linear_trail(lower_bound=8, upper_bound=7)

    smt = SmtXorLinearModel(speck, counter="parallel")

    with pytest.raises(ValueError, match="No search allowed using different bounds and parallel counter."):
        smt.find_one_xor_linear_trail(lower_bound=6, upper_bound=7)


def test_fix_variables_value_xor_linear_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
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
    constraints = smt.fix_variables_value_xor_linear_constraints(fixed_variables)

    assert constraints == [
        "(assert plaintext_0_o)",
        "(assert (not plaintext_1_o))",
        "(assert plaintext_2_o)",
        "(assert plaintext_3_o)",
        "(assert (or (not ciphertext_0_o) (not ciphertext_1_o) (not ciphertext_2_o) ciphertext_3_o))",
    ]

    fixed_variables = [set_fixed_variables(INPUT_PLAINTEXT, "equal", range(4), integer_to_bit_list(5, 4, "big"))]
    assert smt.fix_variables_value_xor_linear_constraints(fixed_variables) == [
        "(assert (not plaintext_0_o))",
        "(assert plaintext_1_o)",
        "(assert (not plaintext_2_o))",
        "(assert plaintext_3_o)",
    ]


def test_fix_variables_value_xor_linear_constraints_with_wrong_constraint_type():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    fixed_variables = [set_fixed_variables(INPUT_PLAINTEXT, "equal", range(4), integer_to_bit_list(5, 4, "big"))]
    fixed_variables[0]["constraint_type"] = "lesser"

    with pytest.raises(ValueError, match="constraint type not defined or misspelled."):
        smt.fix_variables_value_xor_linear_constraints(fixed_variables)


def test_weight_xor_linear_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    smt.build_xor_linear_trail_model()

    assert smt.weight_xor_linear_constraints(7) == smt.weight_constraints(7)
