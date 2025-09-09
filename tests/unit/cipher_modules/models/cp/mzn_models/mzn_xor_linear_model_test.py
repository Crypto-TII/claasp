from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher


def test_and_xor_linear_probability_lat():
    simon = SimonBlockCipher()
    mzn = MznXorLinearModel(simon)

    assert mzn.and_xor_linear_probability_lat(2) == [2, 1, 0, 1, 0, 1, 0, -1]


def test_final_xor_linear_constraints():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    mzn = MznXorLinearModel(speck)
    mzn.build_xor_linear_trail_model(-1)

    assert mzn.final_xor_linear_constraints(-1)[:-1] == [
        "solve:: int_search(p, smallest, indomain_min, complete) minimize sum(p);"
    ]


def test_find_all_xor_linear_trails_with_fixed_weight():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3)
    mzn = MznXorLinearModel(speck)
    trails = mzn.find_all_xor_linear_trails_with_fixed_weight(1, solve_external=False)

    assert len(trails) == 12

    trails = mzn.find_all_xor_linear_trails_with_fixed_weight(1, solver_name="chuffed", solve_external=False)

    assert len(trails) == 12


def test_find_all_xor_linear_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3)
    mzn = MznXorLinearModel(speck)
    trails = mzn.find_all_xor_linear_trails_with_weight_at_most(0, 1, solve_external=False)

    assert len(trails) == 13

    trails = mzn.find_all_xor_linear_trails_with_weight_at_most(0, 1, solver_name="chuffed", solve_external=False)

    assert len(trails) == 13


def test_find_lowest_weight_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    mzn = MznXorLinearModel(speck)
    trail = mzn.find_lowest_weight_xor_linear_trail(solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r4"
    assert eval(trail["components_values"]["cipher_output_3_12_o"]["value"]) >= 0
    assert trail["components_values"]["cipher_output_3_12_o"]["weight"] == 0
    assert trail["total_weight"] == "3.0"

    trail = mzn.find_lowest_weight_xor_linear_trail(solver_name="chuffed", solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r4"
    assert trail["total_weight"] == "3.0"


def test_find_one_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    mzn = MznXorLinearModel(speck)
    trail = mzn.find_one_xor_linear_trail(solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r4"
    assert trail["components_values"]["plaintext"]["weight"] == 0
    assert eval(trail["components_values"]["plaintext"]["value"]) > 0
    assert trail["components_values"]["cipher_output_3_12_o"]["weight"] == 0
    assert eval(trail["components_values"]["cipher_output_3_12_o"]["value"]) >= 0
    assert eval(trail["total_weight"]) >= 0

    trail = mzn.find_one_xor_linear_trail(solver_name="chuffed", solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r4"
    assert trail["components_values"]["plaintext"]["weight"] == 0
    assert eval(trail["components_values"]["plaintext"]["value"]) > 0
    assert eval(trail["total_weight"]) >= 0


def test_find_one_xor_linear_trail_with_fixed_weight():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    mzn = MznXorLinearModel(speck)
    trail = mzn.find_one_xor_linear_trail_with_fixed_weight(3, solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r4"
    assert trail["model_type"] == "xor_linear_one_solution"
    assert trail["total_weight"] == "3.0"

    trail = mzn.find_one_xor_linear_trail_with_fixed_weight(3, solver_name="chuffed", solve_external=False)

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r4"
    assert trail["model_type"] == "xor_linear_one_solution"
    assert trail["total_weight"] == "3.0"


def test_fix_variables_value_xor_linear_constraints():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    mzn = MznXorLinearModel(speck)
    assert mzn.fix_variables_value_xor_linear_constraints(
        [set_fixed_variables("plaintext", "equal", list(range(4)), integer_to_bit_list(5, 4, "big"))]
    ) == ["constraint plaintext_o[0] = 0 /\\ plaintext_o[1] = 1 /\\ plaintext_o[2] = 0 /\\ plaintext_o[3] = 1;"]
    assert mzn.fix_variables_value_xor_linear_constraints(
        [set_fixed_variables("plaintext", "not_equal", list(range(4)), integer_to_bit_list(5, 4, "big"))]
    ) == ["constraint plaintext_o[0] != 0 \\/ plaintext_o[1] != 1 \\/ plaintext_o[2] != 0 \\/ plaintext_o[3] != 1;"]


def test_input_xor_linear_constraints():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    mzn = MznXorLinearModel(speck)
    declarations, constraints = mzn.input_xor_linear_constraints()

    assert declarations[0] == "array[0..31] of var 0..1: plaintext_o;"
    assert declarations[1] == "array[0..63] of var 0..1: key_o;"
    assert (
        declarations[2] == "array[0..6] of var "
        "{0, 1600, 900, 200, 1100, 400, 1300, 600, 1500, 800, 100, 1000, 300, 1200, 500, 1400, 700}: p;"
    )
    assert declarations[3] == "var int: weight = sum(p);"
    assert constraints == []

    fancy = FancyBlockCipher(number_of_rounds=4)
    mzn = MznXorLinearModel(fancy)
    declarations, constraints = mzn.input_xor_linear_constraints()

    assert declarations[0] == "array[0..23] of var 0..1: plaintext_o;"
    assert declarations[1] == "array[0..23] of var 0..1: key_o;"
    assert (
        declarations[2]
        == "array [1..5, 1..4] of int: and2inputs_LAT = array2d(1..5, 1..4, [0,0,0,0,0,0,1,100,0,1,1,100,1,0,1,100,1,1,1,100]);"
    )
    assert declarations[3] == "array[0..127] of var {0, 100, 200, 300, 400, 500, 600}: p;"
    assert constraints == []
