import pytest

from claasp.cipher_modules.models.cp.mzn_models.mzn_semi_deterministic_truncated_xor_differential_model import (
    MznSemiDeterministicTruncatedXorDifferentialModel,
)


from claasp.cipher_modules.models.cp.solvers import CPSAT
from claasp.cipher_modules.models.cp.solvers import CHUFFED
from claasp.cipher_modules.models.utils import differential_truncated_checker_permutation_input_and_output_truncated, integer_to_bit_list, set_fixed_variables
from claasp.cipher_modules.models.cp.minizinc_utils.usefulfunctions import MINIZINC_USEFUL_FUNCTIONS
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ROUND_MODE_HALF, ChachaPermutation
from claasp.name_mappings import (
    INPUT_KEY,
    INPUT_PLAINTEXT,
    SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_LOWEST_SOLUTION,
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
    assert any("var int: weight" in c for c in mzn._variables_list)


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

    
def test_find_optimal_cp_semi_deterministic_truncated_xor_differential_trail():
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

    trail = mzn.find_optimal_cp_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, key], 
        solver_name=CHUFFED, solve_external=True, random_seed=0
    )[0]

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r1"
    assert trail["model_type"] == SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_LOWEST_SOLUTION
    assert trail["solver_name"] == CHUFFED
    assert "total_weight" in trail


def test_counter_based_modadd_semideterministic_probability_sample():
    model = Model()
    model.add_string(MINIZINC_USEFUL_FUNCTIONS)
    model.add_string(
        """
    array[0..31] of var 0..2: delta_carry = array1d(0..31, [0, 0, 0, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0]);
    array[0..31] of var 0..2: a =           array1d(0..31, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    array[0..31] of var 0..2: b =           array1d(0..31, [0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0]);
    array[0..31] of var 0..2: c =           array1d(0..31, [0, 0, 0, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    
array[0..31] of var {100, 41, 19, 9, 4, 2, 1, 0}: costs;
var int: probability;

constraint counter_based_modadd_semideterministic(a, b, c, delta_carry, costs, 32, probability);
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
    array[0..31] of var 0..2: delta_carry = array1d(0..31, [0, 0, 0, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0]);
    array[0..31] of var 0..2: a =           array1d(0..31, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    array[0..31] of var 0..2: b =           array1d(0..31, [0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0]);
    array[0..31] of var 0..2: c =           array1d(0..31, [0, 0, 0, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
array[0..31] of var 0..2: modadd_0_0;
"""
    model.add_string(fixed_block)

    # Bind generated declarations and constraints.
    model.add_string("\n".join(cp_declarations + [f"constraint modadd_0_0[{i}] = c[{i}];" for i in range(32)]))
    model.add_string("\n".join(cp_constraints))
    model.add_string("\n".join([f"constraint delta_carry_modadd_0_0[{i}] = delta_carry[{i}];" for i in range(32)]))
    model.add_string(f"solve minimize {metadata['probability_var']};")

    solver = Solver.lookup("chuffed")
    instance = Instance(solver, model)
    result = instance.solve()

    assert result[metadata["probability_var"]] == 309


def test_counter_based_modadd_semideterministic_probability_700_sample():
    model = Model()
    model.add_string(MINIZINC_USEFUL_FUNCTIONS)
    model.add_string(
        """
    array[0..15] of var 0..2: a = array1d(0..15, [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    array[0..15] of var 0..2: b = array1d(0..15, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    array[0..15] of var 0..2: c = array1d(0..15, [2, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0]);

array[0..15] of var 0..2: delta_carry;
array[0..15] of var {100, 41, 19, 9, 4, 2, 1, 0}: costs;
var int: probability;

constraint counter_based_modadd_semideterministic(a, b, c, delta_carry, costs, 16, probability);
solve minimize probability;
"""
    )

    solver = Solver.lookup("chuffed")
    instance = Instance(solver, model)
    result = instance.solve()

    assert result["probability"] == 700



def test_modular_component_semideterministic_multiple_addends_constraints():
    from claasp.components.modular_component import Modular

    comp = Modular(
        current_round_number=0,
        current_round_number_of_components=0,
        input_id_links=["a", "b", "c"],
        input_bit_positions=[list(range(4)), list(range(4)), list(range(4))],
        output_bit_size=4,
        operation="modadd",
        modulus=2**4,
    )

    cp_declarations, cp_constraints, metadata = comp.cp_semi_deterministic_truncated_xor_differential_constraints()

    assert metadata["probability_var"] == "probability_modadd_0_0"
    assert any("pre_modadd_0_0_3" in declaration for declaration in cp_declarations)
    assert sum("counter_based_modadd_semideterministic" in constraint for constraint in cp_constraints) == 2
    assert any(
        "constraint probability_modadd_0_0 = sum([probability_modadd_0_0_0, probability_modadd_0_0_1]);" in constraint
        for constraint in cp_constraints
    )


def test_find_lowest_semi_deterministic_truncated_xor_differential_trail_speck():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )

    ciphertext = set_fixed_variables(
        component_id="cipher_output_1_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1],
    )

    key = set_fixed_variables(component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64)

    trail = mzn.find_optimal_cp_semi_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key, ciphertext])
    assert trail["total_weight"] == '1.0'
    assert trail["components_values"]["cipher_output_1_12"]["value"] == "???????????????1???????????????1"

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )

    ciphertext = set_fixed_variables(
        component_id="cipher_output_2_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1],
    )

    key = set_fixed_variables(component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64)

    trail = mzn.find_optimal_cp_semi_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key, ciphertext])
    assert trail["total_weight"] == '0.0'
    assert trail["components_values"]["cipher_output_2_12"]["value"] == "???????????????0???????????????1"


@pytest.mark.parametrize(
    "number_of_rounds,output_component_id",
    [
        (2, "cipher_output_1_24"),
        (3, "cipher_output_2_24"),
    ],
)
def test_find_lowest_semi_deterministic_truncated_xor_differential_trail_chacha(number_of_rounds, output_component_id):
    chacha = ChachaPermutation(number_of_rounds=number_of_rounds, round_mode=ROUND_MODE_HALF)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(chacha)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=range(512),
        bit_values=(0,) * 512,
    )
    print(
        f"Starting to find trail for Chacha permutation with {number_of_rounds} rounds and half round mode"
    )
    trail = mzn.find_optimal_cp_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext], solver_name=CPSAT, num_of_processors=8, solve_external=True
    )[0]
    theoretical_probability = float(trail["total_weight"])
    experimental_probability = differential_truncated_checker_permutation_input_and_output_truncated(
        cipher=chacha,
        input_trunc_diff=trail["components_values"]["plaintext"]["value"],
        output_trunc_diff=trail["components_values"][output_component_id]["value"],
        number_of_samples=1 << 10,
        state_size=512,
        seed=0,
    )
    print(
        f"Theoretical probability weight: {theoretical_probability}, Experimental probability weight: {experimental_probability}"
    )
    assert abs(2**experimental_probability - 2**theoretical_probability) / 2**theoretical_probability < 0.2


@pytest.mark.parametrize(
    "input_diff,output_diff",
    [
        ('10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '????1000000000000000000?????????00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000????????????????????????????????00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000?????????????????????????100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000?????????????1000'),
        ('00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000010000000000000001000000000000000000000000000000010000000000000000000000000000000100000000000000010000000000000001000000000000000', '????????????????????????????????????????????????????????????????????????????????????????????1000????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????1000????????????????????????????????????????????????????????????????????????'),
    ],
)
def test_find_lowest_four_round_semi_deterministic_truncated_xor_differential_trail_chacha_with_fixed_variables(input_diff, output_diff):
    number_of_rounds = 4
    output_component_id = "cipher_output_3_24"
    chacha = ChachaPermutation(number_of_rounds=number_of_rounds, round_mode=ROUND_MODE_HALF)
    mzn = MznSemiDeterministicTruncatedXorDifferentialModel(chacha)
    mapping = {'0': 0, '1': 1, '?': 2}

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(512),
        bit_values=integer_to_bit_list(int(input_diff, 2), 512, 'big'), #list(map(int, input_string)),
    )
    cipher_output = set_fixed_variables(
        component_id=output_component_id,
        constraint_type="equal",
        bit_positions=range(512),
        bit_values=[mapping[c] for c in output_diff],
    )
    print(
        f"Starting to find trail for Chacha permutation with {number_of_rounds} rounds and half round mode"
    )
    trail = mzn.find_optimal_cp_semi_deterministic_truncated_xor_differential_trail(
        fixed_values=[plaintext, cipher_output], solver_name=CPSAT, num_of_processors=4, solve_external=True
    )[0]
    assert trail.get("status") == "SATISFIABLE"
    assert output_component_id in trail["components_values"]
    theoretical_probability = float(trail["total_weight"])/100.0
    experimental_probability = differential_truncated_checker_permutation_input_and_output_truncated(
        cipher=chacha,
        input_trunc_diff=trail["components_values"][INPUT_PLAINTEXT]["value"],
        output_trunc_diff=trail["components_values"][output_component_id]["value"],
        number_of_samples=1 << 6,
        state_size=512,
        seed=42,
    )
    experimental_probability = experimental_probability
    print(
        f"Theoretical probability weight: -{theoretical_probability}, Experimental probability weight: {experimental_probability}"
    )
    assert isinstance(trail["components_values"][output_component_id]["value"], str)
    assert len(trail["components_values"][output_component_id]["value"]) == 512
    assert abs(2**(-1*abs(experimental_probability)) - 2**(-1*theoretical_probability)) / 2**(-1*theoretical_probability) < 0.2



    