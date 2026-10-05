from os import path, remove

from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
from claasp.cipher_modules.models.smt.solvers import Z3_EXT
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, SATISFIABLE


def test_find_all_xor_linear_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
    smt = SmtXorLinearModel(speck)
    key = set_fixed_variables(INPUT_KEY, "not_equal", list(range(16)), (0,) * 16)
    trails = smt.find_all_xor_linear_trails_with_weight_at_most(0, 2, fixed_values=[key])

    assert len(trails) == 8


def test_find_lowest_weight_xor_linear_trail():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    trail = smt.find_lowest_weight_xor_linear_trail()
    assert trail["total_weight"] == 1.0


def test_find_lowest_weight_xor_linear_trail_with_log(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    speck = SpeckBlockCipher(number_of_rounds=4)
    smt = SmtXorLinearModel(speck)
    lowest_weight = 3
    log_file_name = f"{speck.id}__smt_find_lowest_weight_xor_linear_trail_from_below__{Z3_EXT}solver.log"
    try:
        trail = smt.find_lowest_weight_xor_linear_trail(log=True)
        with open(log_file_name) as f:
            log_content = f.read()
    finally:
        if path.exists(log_file_name):
            remove(log_file_name)

    assert trail["status"] == SATISFIABLE
    assert trail["total_weight"] == lowest_weight
    log_lines = log_content.splitlines()

    # every weight from 0 to lowest_weight - 1, and only those, is reported as UNSATISFIABLE, in increasing order
    lower_bound_lines = [line for line in log_lines if " has no " in line]
    assert len(lower_bound_lines) == lowest_weight
    for weight, line in enumerate(lower_bound_lines):
        assert line.endswith(f" {speck.id} has no xor_linear trail of weight <= {weight}")
    status_lines = [line for line in log_lines if " (status: " in line]
    assert len(status_lines) == lowest_weight + 1
    for weight, line in enumerate(status_lines[:-1]):
        assert f" {Z3_EXT} terminated the search for weight {weight} in " in line
        assert line.endswith(" (status: UNSATISFIABLE)")
    # a time estimate follows every lower bound except the first one
    assert log_content.count("is expected to terminate in") == lowest_weight - 1

    # the search for lowest_weight is reported as SATISFIABLE, with the weight of the returned trail
    assert f" {Z3_EXT} terminated the search for weight {lowest_weight} in " in status_lines[-1]
    assert status_lines[-1].endswith(" (status: SATISFIABLE)")
    trail_lines = [line for line in log_lines if " has a " in line]
    assert len(trail_lines) == 1
    assert trail_lines[0].endswith(f" {speck.id} has a xor_linear trail of weight {trail['total_weight']}")

    # the log ends with the returned trail
    assert f"'components_values': {trail['components_values']!r}" in log_lines[-1]
    assert f"'total_weight': {trail['total_weight']!r}" in log_lines[-1]


def test_find_one_xor_linear_trail():
    speck = SpeckBlockCipher(number_of_rounds=4)
    smt = SmtXorLinearModel(speck)
    solution = smt.find_one_xor_linear_trail()
    assert str(solution["cipher"]) == "speck_p32_k64_o32_r4"
    assert solution["solver_name"] == Z3_EXT
    assert int(solution["components_values"]["modadd_0_1_i"]["value"], 16) >= 0
    assert solution["components_values"]["modadd_0_1_i"]["weight"] == 0
    assert solution["components_values"]["modadd_0_1_i"]["sign"] == 1
    assert int(solution["components_values"]["xor_0_4_o"]["value"], 16) >= 0
    assert solution["components_values"]["xor_0_4_o"]["weight"] == 0
    assert solution["components_values"]["xor_0_4_o"]["sign"] == 1


def test_find_one_xor_linear_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    result = smt.find_one_xor_linear_trail_with_fixed_weight(7)
    assert result["total_weight"] == 7.0


def test_fix_variables_value_xor_linear_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    fixed_variables = [set_fixed_variables(INPUT_PLAINTEXT, "equal", range(4), integer_to_bit_list(5, 4, "big"))]
    assert smt.fix_variables_value_xor_linear_constraints(fixed_variables) == [
        "(assert (not plaintext_0_o))",
        "(assert plaintext_1_o)",
        "(assert (not plaintext_2_o))",
        "(assert plaintext_3_o)",
    ]
