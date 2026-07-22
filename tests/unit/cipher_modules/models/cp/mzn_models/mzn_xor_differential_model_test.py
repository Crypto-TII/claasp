from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import (
    MznXorDifferentialModel,
    and_xor_differential_probability_ddt,
)
from claasp.cipher_modules.models.cp.solvers import CPSAT
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
from claasp.name_mappings import INPUT_PLAINTEXT, UNSATISFIABLE


def test_and_xor_differential_probability_ddt():
    assert and_xor_differential_probability_ddt(2) == [4, 0, 2, 2, 2, 2, 2, 2]


def test_find_all_xor_differential_trails_with_fixed_weight():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
    mzn = MznXorDifferentialModel(speck)
    trails = mzn.find_all_xor_differential_trails_with_fixed_weight(1, solver_name=CPSAT, solve_external=True)

    assert len(trails) == 6

    trails = mzn.find_all_xor_differential_trails_with_fixed_weight(1, solver_name=CPSAT, solve_external=False)

    assert len(trails) == 6


def test_solving_unsatisfiability():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
    mzn = MznXorDifferentialModel(speck)
    trails = mzn.find_one_xor_differential_trail_with_fixed_weight(1, solver_name=CPSAT, solve_external=True)

    assert trails["status"] == UNSATISFIABLE

    trails = mzn.find_one_xor_differential_trail_with_fixed_weight(1, solver_name=CPSAT, solve_external=False)

    assert trails["status"] == UNSATISFIABLE


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
    mzn = MznXorDifferentialModel(speck)
    trails = mzn.find_all_xor_differential_trails_with_weight_at_most(1, 0, solver_name=CPSAT, solve_external=True)

    assert len(trails) == 7

    trails = mzn.find_all_xor_differential_trails_with_weight_at_most(1, 0, solver_name=CPSAT, solve_external=False)

    assert len(trails) == 7


def test_find_all_xor_differential_trails_with_weight_at_most_unsat_returns_empty_list():
    cipher = SboxCipher(bit_size=3, lookup_table=[0, 1, 2, 3, 4, 5, 6, 7])
    mzn = MznXorDifferentialModel(cipher)

    zero_weight_trails = mzn.find_all_xor_differential_trails_with_weight_at_most(
        0, 0, solver_name=CPSAT, solve_external=False
    )
    assert len(zero_weight_trails) > 0
    assert all(t["total_weight"] == "0.0" for t in zero_weight_trails)

    trails = mzn.find_all_xor_differential_trails_with_weight_at_most(1, 1, solver_name=CPSAT, solve_external=False)

    assert trails == []


def test_find_lowest_weight_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    mzn = MznXorDifferentialModel(speck)
    trail = mzn.find_lowest_weight_xor_differential_trail(solver_name=CPSAT, solve_external=True)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r5"
    assert trail["total_weight"] == "9.0"
    assert int(trail["components_values"]["cipher_output_4_12"]["value"], base=16) >= 0
    assert trail["components_values"]["cipher_output_4_12"]["weight"] == 0

    trail = mzn.find_lowest_weight_xor_differential_trail(solver_name=CPSAT, solve_external=True)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r5"
    assert trail["total_weight"] == "9.0"
    assert int(trail["components_values"]["cipher_output_4_12"]["value"], base=16) >= 0
    assert trail["components_values"]["cipher_output_4_12"]["weight"] == 0

    trail = mzn.find_lowest_weight_xor_differential_trail(solver_name=CPSAT, solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r5"
    assert trail["total_weight"] == "9.0"
    assert int(trail["components_values"]["cipher_output_4_12"]["value"], base=16) >= 0
    assert trail["components_values"]["cipher_output_4_12"]["weight"] == 0


def test_find_one_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=2)
    mzn = MznXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )
    trail = mzn.find_one_xor_differential_trail([plaintext], CPSAT, solve_external=True)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r2"
    assert trail["model_type"] == "xor_differential_one_solution"
    assert int(trail["components_values"]["cipher_output_1_12"]["value"], base=16) >= 0
    assert trail["components_values"]["cipher_output_1_12"]["weight"] == 0
    assert float(trail["total_weight"]) >= 0

    trail = mzn.find_one_xor_differential_trail([plaintext], CPSAT, solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r2"
    assert trail["model_type"] == "xor_differential_one_solution"
    assert int(trail["components_values"]["cipher_output_1_12"]["value"], base=16) >= 0
    assert trail["components_values"]["cipher_output_1_12"]["weight"] == 0
    assert float(trail["total_weight"]) >= 0


def test_find_one_xor_differential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=5)
    mzn = MznXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )
    trail = mzn.find_one_xor_differential_trail_with_fixed_weight(9, [plaintext], CPSAT, solve_external=True)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r5"
    assert trail["model_type"] == "xor_differential_one_solution"
    assert int(trail["components_values"]["intermediate_output_0_5"]["value"], base=16) >= 0
    assert trail["components_values"]["intermediate_output_0_5"]["weight"] == 0
    assert int(trail["components_values"]["intermediate_output_1_11"]["value"], base=16) >= 0
    assert trail["components_values"]["intermediate_output_1_11"]["weight"] == 0
    assert int(trail["components_values"]["xor_3_8"]["value"], base=16) >= 0
    assert trail["components_values"]["xor_3_8"]["weight"] == 0
    assert trail["total_weight"] == "9.0"

    trail = mzn.find_one_xor_differential_trail_with_fixed_weight(9, [plaintext], CPSAT, solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r5"
    assert trail["model_type"] == "xor_differential_one_solution"
    assert int(trail["components_values"]["intermediate_output_0_5"]["value"], base=16) >= 0
    assert trail["components_values"]["intermediate_output_0_5"]["weight"] == 0
    assert int(trail["components_values"]["intermediate_output_1_11"]["value"], base=16) >= 0
    assert trail["components_values"]["intermediate_output_1_11"]["weight"] == 0
    assert int(trail["components_values"]["xor_3_8"]["value"], base=16) >= 0
    assert trail["components_values"]["xor_3_8"]["weight"] == 0
    assert trail["total_weight"] == "9.0"



