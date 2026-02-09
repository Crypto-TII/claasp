import pytest

from claasp.cipher_modules.models.cp.mzn_models.mzn_semi_deterministic_truncated_xor_differential_model import (
    MznSemiDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.cp.solvers import CHUFFED
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.cipher_modules.models.cp.minizinc_utils.usefulfunctions import MINIZINC_USEFUL_FUNCTIONS
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import (
    INPUT_KEY,
    INPUT_PLAINTEXT,
    SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_ONE_SOLUTION,
)
from minizinc import Model, Solver, Instance


def test_build_semi_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=1)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(speck)
    fixed_variables = [set_fixed_variables(INPUT_KEY, "equal", range(64), (0,) * 64)]
    mzn.build_cp_semi_deterministic_truncated_xor_differential_trail(fixed_variables)

    assert any("counter_based_modadd_semideterministic" in c for c in mzn.model_constraints)
    assert any("probability_modadd_0_1" in c for c in mzn.model_constraints)
    assert any("var int: weight" in c for c in mzn.model_constraints)


def test_find_one_semi_deterministic_truncated_xor_differential_trail_external():
    speck = SpeckBlockCipher(number_of_rounds=1)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(speck)
    block_size, key_size = speck.inputs_bit_size
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=range(block_size),
        bit_values=(0,) * block_size,
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY,
        constraint_type="equal",
        bit_positions=range(key_size),
        bit_values=(0,) * key_size,
    )

    trail = mzn.find_one_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, key], solver_name=CHUFFED, solve_external=True, random_seed=0
    )

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r1"
    assert trail["model_type"] == SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_ONE_SOLUTION
    assert trail["solver_name"] == CHUFFED
    assert "total_weight" in trail


def test_find_lowest_cp_semi_deterministic_truncated_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=1)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(speck)
    block_size, key_size = speck.inputs_bit_size
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=range(block_size),
        bit_values=(0,) * block_size,
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY,
        constraint_type="equal",
        bit_positions=range(key_size),
        bit_values=(0,) * key_size,
    )

    trail = mzn.find_lowest_cp_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, key], solver_name=CHUFFED, solve_external=True, random_seed=0
    )

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r1"
    assert trail["model_type"] == SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_ONE_SOLUTION
    assert trail["solver_name"] == CHUFFED
    assert "total_weight" in trail


def test_counter_based_modadd_semideterministic_probability_sample():
    model = Model()
    model.add_string(MINIZINC_USEFUL_FUNCTIONS)
    model.add_string(
        """
    array[0..31] of var 0..2: a = array1d(0..31, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    array[0..31] of var 0..2: b = array1d(0..31, [0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 2, 1, 1, 0]);
    array[0..31] of var 0..2: c = array1d(0..31, [0, 0, 0, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0]);
    array[0..31] of var 0..2: delta_carry = array1d(0..31, [0, 0, 0, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
var 0..31: p;
array[0..31] of var {100, 41, 19, 9, 4, 0}: costs;
var int: probability;

constraint counter_based_modadd_semideterministic(a, b, c, delta_carry, p, costs, 32, probability);
    solve minimize probability;
"""
    )

    solver = Solver.lookup("chuffed")
    instance = Instance(solver, model)
    result = instance.solve()

    assert result["probability"] == 309


def test_modular_component_semideterministic_probability_sample():
    from claasp.components.modular_component import Modular
    from claasp.name_mappings import WORD_OPERATION

    comp = Modular(
        current_round_number=0,
        current_round_number_of_components=0,
        input_id_links=["a", "b"],
        input_bit_positions=[list(range(32)), list(range(32))],
        output_bit_size=32,
        operation="modadd",
        modulus=2**32,
    )

    cp_declarations, cp_constraints, metadata = comp.cp_semi_deterministic_truncated_xor_differential_constraints()

    model = Model()
    model.add_string(MINIZINC_USEFUL_FUNCTIONS)

    fixed_block = """
array[0..31] of var 0..2: a = array1d(0..31, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
array[0..31] of var 0..2: b = array1d(0..31, [0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 2, 1, 1, 0]);
array[0..31] of var 0..2: c = array1d(0..31, [0, 0, 0, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0]);
array[0..31] of var 0..2: delta = array1d(0..31, [0, 0, 0, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
array[0..31] of var 0..2: modadd_0_0;
"""
    model.add_string(fixed_block)

    # Bind generated declarations and constraints.
    model.add_string("\n".join(cp_declarations + [f"constraint modadd_0_0[{i}] = c[{i}];" for i in range(32)]))
    model.add_string("\n".join(cp_constraints))
    model.add_string("\n".join([f"constraint delta_carry_modadd_0_0[{i}] = delta[{i}];" for i in range(32)]))
    model.add_string(f"solve minimize {metadata['probability_var']};")

    solver = Solver.lookup("chuffed")
    instance = Instance(solver, model)
    result = instance.solve()

    assert result[metadata["probability_var"]] == 309


def test_find_one_semi_deterministic_truncated_xor_differential_trail_weight_zero_patterns():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )
    key = set_fixed_variables(component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64)

    trail = mzn.find_lowest_cp_semi_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
    assert trail["total_weight"] == '0.0'
    assert trail["components_values"]["intermediate_output_0_6"]["value"] == "????100000000000????100000000011"

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )
    key = set_fixed_variables(component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64)

    trail = mzn.find_lowest_cp_semi_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
    assert trail["total_weight"] == '0.0'
    assert trail["components_values"]["cipher_output_2_12"]["value"] == "???????????????0????????????????"
