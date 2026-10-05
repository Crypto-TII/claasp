import pytest

from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.cipher_modules.models.smt.smt_models.smt_cipher_model import SmtCipherModel
from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.smt.solvers import MATHSAT_EXT, YICES_EXT, Z3_EXT
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.name_mappings import INPUT_PLAINTEXT, SATISFIABLE, UNSATISFIABLE


def test_solve():
    # testing with Z3
    tea = TeaBlockCipher(number_of_rounds=32)
    smt = SmtCipherModel(tea)
    smt.build_cipher_model()
    solution = smt.solve("cipher", solver_name=Z3_EXT)
    assert str(solution["cipher"]) == "tea_p64_k128_o64_r32"
    assert solution["status"] == SATISFIABLE
    assert int(solution["components_values"]["modadd_0_3"]["value"], 16) >= 0
    assert int(solution["components_values"]["cipher_output_31_16"]["value"], 16) >= 0
    # testing with the other solvers
    simon = SimonBlockCipher(number_of_rounds=32)
    for solver_name in (MATHSAT_EXT, YICES_EXT):
        smt = SmtCipherModel(simon)
        smt.build_cipher_model()
        solution = smt.solve("cipher", solver_name=solver_name)
        assert str(solution["cipher"]) == "simon_p32_k64_o32_r32"
        assert solution["solver_name"] == solver_name
        assert solution["status"] == SATISFIABLE
        assert int(solution["components_values"]["rot_0_3"]["value"], 16) >= 0
        assert int(solution["components_values"]["cipher_output_31_13"]["value"], 16) >= 0


def test_solver_names():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtModel(speck)
    solver_names = smt.solver_names()
    assert isinstance(solver_names, list)
    assert len(solver_names) > 0
    # Check that each entry has the required keys
    for solver in solver_names:
        assert "solver_brand_name" in solver
        assert "solver_name" in solver
        assert "keywords" not in solver  # verbose=False by default

    # Test verbose mode
    verbose_solver_names = smt.solver_names(verbose=True)
    assert isinstance(verbose_solver_names, list)
    # All SMT solvers are external, so they should have keywords when verbose=True
    for solver in verbose_solver_names:
        assert "keywords" in solver


def test_fix_variables_value_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtModel(speck)
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
    assert smt.fix_variables_value_constraints(fixed_variables) == [
        "(assert plaintext_0)",
        "(assert (not plaintext_1))",
        "(assert plaintext_2)",
        "(assert plaintext_3)",
        "(assert (or (not ciphertext_0) (not ciphertext_1) (not ciphertext_2) ciphertext_3))",
    ]

    fixed_variables = [set_fixed_variables(INPUT_PLAINTEXT, "equal", range(4), integer_to_bit_list(5, 4, "big"))]
    assert smt.fix_variables_value_constraints(fixed_variables) == [
        "(assert (not plaintext_0))",
        "(assert plaintext_1)",
        "(assert (not plaintext_2))",
        "(assert plaintext_3)",
    ]

    fixed_variables = [set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(4), integer_to_bit_list(5, 4, "big"))]
    assert smt.fix_variables_value_constraints(fixed_variables) == [
        "(assert (or plaintext_0 (not plaintext_1) plaintext_2 (not plaintext_3)))"
    ]

    smt = SmtXorDifferentialModel(speck)
    cipher_output_id = speck.all_components_ids()[-1]
    fixed_values = [set_fixed_variables(INPUT_PLAINTEXT, "equal", range(32), [0] * 31 + [1])]
    fixed_values.append(set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(32), [0] * 31 + [1]))
    trail = smt.find_one_xor_differential_trail(fixed_values=fixed_values)
    assert trail["status"] == UNSATISFIABLE
    assert trail["total_weight"] is None
    assert trail["components_values"] == {}

    fixed_values = [set_fixed_variables(INPUT_PLAINTEXT, "equal", range(32), [0] * 31 + [1])]
    trail = smt.find_one_xor_differential_trail(fixed_values=fixed_values)
    assert trail["status"] == SATISFIABLE
    assert trail["components_values"][INPUT_PLAINTEXT]["value"] == "0x00000001"
    assert cipher_output_id in trail["components_values"]


def test_fix_variables_value_constraints_with_wrong_constraint_type():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtModel(speck)
    fixed_variables = [set_fixed_variables(INPUT_PLAINTEXT, "equal", range(4), integer_to_bit_list(5, 4, "big"))]
    fixed_variables[0]["constraint_type"] = "lesser"

    with pytest.raises(ValueError, match="constraint type not defined or misspelled."):
        smt.fix_variables_value_constraints(fixed_variables)


def test_get_xor_probability_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtModel(speck)
    template = [[(0, 0), (1, 1)], [(1, 0), (0, 2)]]

    assert smt.get_xor_probability_constraints(["a", "b", "c"], template) == [
        "(assert (or a (not b)))",
        "(assert (or (not a) c))",
    ]


def test_model_constraints():
    with pytest.raises(Exception):
        speck = SpeckBlockCipher(number_of_rounds=4)
        smt = SmtModel(speck)
        smt.model_constraints()


def test_properties():
    speck = SpeckBlockCipher(number_of_rounds=4)
    smt = SmtModel(speck)

    assert smt.cipher_id == "speck_p32_k64_o32_r4"
    assert smt.sboxes_ddt_templates == {}
    assert smt.sboxes_lat_templates == {}


def test_weight_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorDifferentialModel(speck)
    smt.build_xor_differential_trail_model()
    assert len(smt.weight_constraints(7)) == 2

    variables, constraints = smt.weight_constraints(0)
    hw_list = [variable_id for variable_id in smt._variables_list if variable_id.startswith("hw_")]
    assert variables == []
    assert constraints == [f"(assert (not {variable}))" for variable in hw_list]

    smt = SmtXorDifferentialModel(speck, counter="parallel")
    smt.build_xor_differential_trail_model()
    assert len(smt.weight_constraints(7)) == 2


def test_parallel_counter_branch():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtModel(speck, counter="parallel")

    variables, constraints = smt._parallel_counter(["hw_0", "hw_1", "hw_2"], 5)

    assert variables
    assert constraints
    assert any(variable.startswith("r_") for variable in variables)
    assert "dummy_hw_3" in variables
    # the weight 5 = 0b101 is fixed on the result bits, MSB first
    assert constraints[-3:] == ["(assert r_0_0_0)", "(assert (not r_0_0_1))", "(assert r_0_0_2)"]
