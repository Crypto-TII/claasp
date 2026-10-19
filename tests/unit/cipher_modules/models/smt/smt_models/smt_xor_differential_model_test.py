from os import path, remove

from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.smt.solvers import Z3_EXT
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import SATISFIABLE


def test_find_all_xor_differential_trails_with_weight_at_most():
    speck = SpeckBlockCipher(number_of_rounds=5)
    smt = SmtXorDifferentialModel(speck)
    trails = smt.find_all_xor_differential_trails_with_weight_at_most(10, 9)
    assert len(trails) == 28


def test_find_lowest_weight_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    smt = SmtXorDifferentialModel(speck)
    trail = smt.find_lowest_weight_xor_differential_trail()
    assert trail["total_weight"] == 9.0


def test_find_lowest_weight_xor_differential_trail_with_log(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    speck = SpeckBlockCipher(number_of_rounds=4)
    smt = SmtXorDifferentialModel(speck)
    start_weight = 2
    lowest_weight = 5
    log_file_name = f"{speck.id}__smt_find_lowest_weight_xor_differential_trail_from_below__{Z3_EXT}solver.log"
    try:
        trail = smt.find_lowest_weight_xor_differential_trail(start_weight=start_weight, log=True)
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
        assert line.endswith(f" {speck.id} has no xor_differential trail of weight <= {weight}")
    status_lines = [line for line in log_lines if " (status: " in line]
    assert len(status_lines) == lowest_weight - start_weight + 1
    for weight, line in enumerate(status_lines[:-1], start=start_weight):
        assert f" {Z3_EXT} terminated the search for weight {weight} in " in line
        assert line.endswith(" (status: UNSATISFIABLE)")
    # a time estimate follows every lower bound except the first one
    assert log_content.count("is expected to terminate in") == lowest_weight - start_weight - 1

    # the search for lowest_weight is reported as SATISFIABLE, with the weight of the returned trail
    assert f" {Z3_EXT} terminated the search for weight {lowest_weight} in " in status_lines[-1]
    assert status_lines[-1].endswith(" (status: SATISFIABLE)")
    trail_lines = [line for line in log_lines if " has a " in line]
    assert len(trail_lines) == 1
    assert trail_lines[0].endswith(f" {speck.id} has a xor_differential trail of weight {trail['total_weight']}")

    # the log ends with the returned trail
    assert f"'components_values': {trail['components_values']!r}" in log_lines[-1]
    assert f"'total_weight': {trail['total_weight']!r}" in log_lines[-1]


def test_find_one_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=5)
    smt = SmtXorDifferentialModel(speck)
    solution = smt.find_one_xor_differential_trail()
    assert str(solution["cipher"]) == "speck_p32_k64_o32_r5"
    assert solution["solver_name"] == Z3_EXT
    assert int(solution["components_values"]["intermediate_output_0_6"]["value"], 16) >= 0
    assert solution["components_values"]["intermediate_output_0_6"]["weight"] == 0
    assert int(solution["components_values"]["cipher_output_4_12"]["value"], 16) >= 0
    assert solution["components_values"]["cipher_output_4_12"]["weight"] == 0


def test_find_one_xor_differential_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorDifferentialModel(speck)
    result = smt.find_one_xor_differential_trail_with_fixed_weight(3)
    assert result["total_weight"] == 3.0
