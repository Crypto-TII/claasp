import pytest

from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.smt.solvers import MATHSAT_EXT, YICES_EXT, Z3_EXT
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, SATISFIABLE, XOR_DIFFERENTIAL

speck_5rounds = SpeckBlockCipher(number_of_rounds=5)


def test_build_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=1)
    smt = SmtXorDifferentialModel(speck)
    smt.build_xor_differential_trail_model()
    constraints = smt.model_constraints

    assert constraints[:2] == ["(set-option :print-success false)", "(set-logic QF_UF)"]
    assert constraints[-3:] == ["(check-sat)", "(get-model)", "(exit)"]
    assert "(declare-const plaintext_0 Bool)" in constraints
    assert not any(variable.startswith("dummy_hw_") for variable in smt._variables_list)


def test_find_all_xor_differential_trails_with_fixed_weight():
    smt = SmtXorDifferentialModel(speck_5rounds)
    trails = smt.find_all_xor_differential_trails_with_fixed_weight(9)

    assert len(trails) == 2
    assert all(int(trail["total_weight"]) == 9 for trail in trails)
    assert trails[-1]["test_name"] == "find_all_xor_differential_trails_with_fixed_weight"


def test_find_all_xor_differential_trails_with_fixed_weight_parallel():
    smt = SmtXorDifferentialModel(speck_5rounds, counter="parallel")
    trails = smt.find_all_xor_differential_trails_with_fixed_weight(9)

    assert len(trails) == 2
    assert all(int(trail["total_weight"]) == 9 for trail in trails)


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = speck_5rounds
    smt = SmtXorDifferentialModel(speck)
    trails = smt.find_all_xor_differential_trails_with_weight_at_most(10, 9)

    assert len(trails) == 28
    assert all(trail["test_name"] == "find_all_xor_differential_trails_with_weight_at_most" for trail in trails)


def test_find_all_xor_differential_trails_with_weight_at_most_accepts_default_min_weight_and_no_crash():
    """Test that single-argument call finds all trails 'at most' that weight (min_weight=0 by default)."""
    cipher = SboxCipher(bit_size=3, lookup_table=[0, 1, 2, 3, 4, 5, 6, 7])
    smt = SmtXorDifferentialModel(cipher)

    # Single-arg call: find all trails "at most 1 weight" → [0, 1]
    trails_default_range = smt.find_all_xor_differential_trails_with_weight_at_most(1)
    assert len(trails_default_range) == 7
    assert all(float(t["total_weight"]) == 0.0 for t in trails_default_range)

    # Two-arg call: find all trails with weight in [0, 17]
    trails = smt.find_all_xor_differential_trails_with_weight_at_most(17, 0)
    assert len(trails) == 7
    assert all(float(t["total_weight"]) == 0.0 for t in trails)


def test_find_lowest_weight_xor_differential_trail():
    speck = speck_5rounds
    smt = SmtXorDifferentialModel(speck)
    trail = smt.find_lowest_weight_xor_differential_trail()

    assert trail["total_weight"] == 9.0
    assert trail["test_name"] == "find_lowest_weight_xor_differential_trail"


def test_find_lowest_weight_xor_differential_trail_parallel():
    speck = speck_5rounds
    smt = SmtXorDifferentialModel(speck, counter="parallel")
    trail = smt.find_lowest_weight_xor_differential_trail()

    assert int(trail["total_weight"]) == 9


def test_find_one_xor_differential_trail():
    speck = speck_5rounds
    smt = SmtXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=range(32),
        bit_values=(0,) * 32,
    )
    trail = smt.find_one_xor_differential_trail(fixed_values=[plaintext])

    assert str(trail["cipher"]) == "speck_p32_k64_o32_r5"
    assert trail["model_type"] == XOR_DIFFERENTIAL
    assert trail["solver_name"] == Z3_EXT
    assert trail["status"] == SATISFIABLE
    assert trail["test_name"] == "find_one_xor_differential_trail"
    assert int(trail["components_values"]["intermediate_output_0_6"]["value"], 16) >= 0
    assert trail["components_values"]["intermediate_output_0_6"]["weight"] == 0
    assert int(trail["components_values"]["cipher_output_4_12"]["value"], 16) >= 0
    assert trail["components_values"]["cipher_output_4_12"]["weight"] == 0

    # a tight upper bound keeps MathSAT and Yices fast: with the default one (32) they take minutes
    for solver_name in (MATHSAT_EXT, YICES_EXT):
        trail = smt.find_one_xor_differential_trail(fixed_values=[plaintext], upper_bound=9, solver_name=solver_name)

        assert trail["solver_name"] == solver_name
        assert trail["status"] == SATISFIABLE
        assert int(trail["total_weight"]) <= 9


def test_find_one_xor_differential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorDifferentialModel(speck)
    result = smt.find_one_xor_differential_trail(lower_bound=3, upper_bound=3)

    assert int(result["total_weight"]) == 3


def test_find_one_xor_differential_trail_with_fixed_weight_parallel():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorDifferentialModel(speck, counter="parallel")
    result = smt.find_one_xor_differential_trail(lower_bound=3, upper_bound=3)

    assert int(result["total_weight"]) == 3


def test_find_one_xor_differential_trail_with_wrong_bounds():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorDifferentialModel(speck)

    with pytest.raises(ValueError, match="lower_bound must be <= upper_bound"):
        smt.find_one_xor_differential_trail(lower_bound=4, upper_bound=3)

    smt = SmtXorDifferentialModel(speck, counter="parallel")

    with pytest.raises(ValueError, match="No search allowed using different bounds and parallel counter."):
        smt.find_one_xor_differential_trail(lower_bound=2, upper_bound=3)


def test_build_xor_differential_trail_model_fixed_weight_and_mathsat():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorDifferentialModel(speck)
    smt.build_xor_differential_trail_model(3)
    result = smt.solve(XOR_DIFFERENTIAL, solver_name=MATHSAT_EXT)

    assert result["status"] == SATISFIABLE
    assert int(result["total_weight"]) == 3


def test_get_operands():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="equal", bit_positions=range(32), bit_values=(0,) * 31 + (1,)
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    trail = smt.find_one_xor_differential_trail(fixed_values=[plaintext, key])
    operands = smt.get_operands(trail)

    assert len(operands) == sum(speck.inputs_bit_size)
    assert operands[:2] == ["plaintext_0", "plaintext_1"]
    assert operands[31] == "(not plaintext_31)"
    assert operands[-1] == "key_63"
