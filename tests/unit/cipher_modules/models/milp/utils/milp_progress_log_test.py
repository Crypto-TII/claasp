import contextlib
import io
import os
import sys
import tempfile
import time

import pytest

from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
from claasp.cipher_modules.models.milp.utils.milp_progress_log import (
    _CplexProgressParser,
    _GlpkProgressParser,
    _GurobiImprovingSolutions,
    _GurobiProgressParser,
    _HighsImprovingSolutions,
    _HighsProgressParser,
    _ScipProgressParser,
    create_progress_log,
    format_trail,
)
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher

# log files that the solvers write in the working directory
SOLVER_LOG_FILE_NAMES = ("HiGHS.log", "gurobi.log")


def test_cplex_progress_parser():
    parser = _CplexProgressParser()
    assert parser.parse("   Node  Left     Objective  IInf  Best Integer    Best Bound    ItCnt     Gap") is None
    assert parser.parse("Elapsed time = 0.05 sec. (54.00 ticks, tree = 0.02 MB, solutions = 0)") is None
    assert parser.parse("Clique table members: 9.") is None
    line = "      0     0        0.0000   142                      0.0000      106         "
    assert parser.parse(line) == (0.0, None, None)
    line = "*     0+    0                          900.0000        0.0000           100.00%"
    assert parser.parse(line) == (0.0, 900.0, None)
    line = "      0     0        0.0000    49      200.0000        0.0000       69  100.00%"
    assert parser.parse(line) == (0.0, 200.0, None)
    line = "      0     0        cutoff              0.0000        0.0000       69    0.00%"
    assert parser.parse(line) == (0.0, 0.0, None)
    line = "*     1     1      integral     0        0.0000        0.0000      111    0.00%"
    assert parser.parse(line) == (0.0, 0.0, None)
    line = "      0     0        0.5000    70      900.0000      Cuts: 45      312   99.94%"
    assert parser.parse(line) == (None, 900.0, None)
    line = "   1234   456      300.1234    23      900.0000      280.5000    45678   68.83%"
    assert parser.parse(line) == (280.5, 900.0, None)


def test_glpk_progress_parser():
    parser = _GlpkProgressParser()
    line = "+   821: mip =     not found yet >=              -inf        (1; 0)"
    assert parser.parse(line) == (float("-inf"), None, None)
    line = "+  9054: >>>>>   3.000000000e+03 >=   3.000000000e+00  99.9% (122; 7)"
    assert parser.parse(line) == (3.0, 3000.0, None)
    line = "+182309: mip =   6.400000000e+03 >=   6.200000000e+01  99.0% (2461; 137)"
    assert parser.parse(line) == (62.0, 6400.0, None)
    line = "+ 25401: mip =   9.000000000e+02 >=     tree is empty   0.0% (0; 4479)"
    assert parser.parse(line) == (None, 900.0, None)
    assert parser.parse("Time used: 60.0 secs.  Memory used: 8.6 Mb.") is None
    assert parser.parse("      0: obj =   0.000000000e+00 inf =   1.000e+00 (1)") is None


def test_gurobi_progress_parser():
    parser = _GurobiProgressParser()
    assert parser.parse(" Expl Unexpl |  Obj  Depth IntInf | Incumbent    BestBd   Gap | It/Node Time") is None
    assert parser.parse("Explored 1 nodes (154 simplex iterations) in 0.01 seconds (0.01 work units)") is None
    line = "     0     0    0.10277    0   78          -    0.10277      -     -    0s"
    assert parser.parse(line) == (0.10277, None, None)
    line = "     0     0    0.10277    0   78 2500.00000    0.10277   100%     -    0s"
    assert parser.parse(line) == (0.10277, 2500.0, None)
    line = "H    0     0                     200.0000000    0.10277   100%     -    0s"
    assert parser.parse(line) == (0.10277, 200.0, None)
    line = "*  123    45               12    900.0000000  270.00000  70.0%  12.3    5s"
    assert parser.parse(line) == (270.0, 900.0, None)
    line = " 12345  2345  456.12345   34   56  900.00000  456.12345  49.3%  45.6  120s"
    assert parser.parse(line) == (456.12345, 900.0, None)


def test_highs_progress_parser():
    parser = _HighsProgressParser()
    header = "Src  Proc. InQueue |  Leaves   Expl. | BestBound       BestSol              Gap |   Cuts   InLp Confl. |"
    assert parser.parse(header) is None
    assert parser.parse("Objective function is integral with scale 0.01") is None

    line = " L     305     106        81   0.00%   87.25490196     2700              96.77%     4185      6   1192"
    line += "    138983    13.1s"
    assert parser.parse(line) == (87.25490196, 2700.0, 0.0)
    line = "     10001     144      3786  43.39%   362.1385084     900               59.76%     4306     38   9809"
    line += "     1037k    95.1s"
    assert parser.parse(line) == (362.1385084, 900.0, 43.39)
    line = "         0       0         0   0.00%   0               inf                  inf        0      0      0"
    line += "         0     0.0s"
    assert parser.parse(line) == (0.0, float("inf"), 0.0)


def test_scip_progress_parser():
    parser = _ScipProgressParser()
    row = " 19.7s|  2100 |   399 |410651 | 129.4 |    55M |  30 | 272 |2243 |1340 |1491 |  1 |2670 |1641 |"
    row += " 3.704204e+02 | 9.000000e+02 | 142.97%|  27.16%"
    assert parser.parse(row) is None  # the columns are unknown before the header

    header = " time | node  | left  |LP iter|LP it/n|mem/heur|mdpt |vars |cons |rows |cuts |sepa|confs|strbr|"
    header += "  dualbound   | primalbound  |  gap   | compl. "
    assert parser.parse(header) is None
    assert parser.parse(row) == (370.4204, 900.0, 27.16)
    row_without_trail = "p 0.1s|     1 |     0 |     0 |     - |shiftand|   0 | 320 |1595 |1579 |   0 |  0 |  16 |"
    row_without_trail += "   0 | 0.000000e+00 |       --     |    Inf | unknown"
    assert parser.parse(row_without_trail) == (0.0, None, None)
    assert parser.parse("SCIP Status        : problem is solved [optimal solution found]") is None


def test_highs_improving_solutions_are_read_incrementally():
    improving_solutions = _HighsImprovingSolutions(f"highs_improving_solutions_test_{time.time()}")
    first_solution = "Objective 3700\n# Columns -2\ny_1 3700\nx_5 1\n"
    second_solution = "Objective 2000\n# Columns -3\ny_1 2000\nx_5 1\nx_7 1\n"
    try:
        assert improving_solutions.solver_command_arguments().startswith(" --options_file ")
        options_file_paths = [path for path in improving_solutions.file_paths() if path.endswith("_options.txt")]
        assert len(options_file_paths) == 1 and os.path.exists(options_file_paths[0])
        assert improving_solutions.read_new_solutions() == []

        with open(improving_solutions.file_path, "w") as solutions_file:
            solutions_file.write(first_solution + second_solution[:30])
        assert improving_solutions.read_new_solutions() == [(3700.0, "y_1 3700\nx_5 1")]

        with open(improving_solutions.file_path, "a") as solutions_file:
            solutions_file.write(second_solution[30:])
        assert improving_solutions.read_new_solutions() == [(2000.0, "y_1 2000\nx_5 1\nx_7 1")]
        assert improving_solutions.read_new_solutions() == []
    finally:
        for file_path in improving_solutions.file_paths():
            if os.path.exists(file_path):
                os.remove(file_path)


def test_gurobi_improving_solutions_are_read_when_complete():
    base_path = f"gurobi_improving_solutions_test_{time.time()}"
    improving_solutions = _GurobiImprovingSolutions(base_path)
    solutions = [
        f"# Solution for model obj\n# Objective value = {objective}\ny_1 {objective}\n" for objective in (26, 9, 2)
    ]
    file_paths = [f"{base_path}_improving_{index}.sol" for index in range(len(solutions))]
    try:
        assert improving_solutions.solver_command_arguments() == f" SolFiles={base_path}_improving"
        assert improving_solutions.read_new_solutions() == []
        with open(file_paths[0], "w") as solution_file:
            solution_file.write(solutions[0])
        # the file has just been modified, hence it may not be completely written
        assert improving_solutions.read_new_solutions() == []
        settled_time = time.time() - 3
        os.utime(file_paths[0], (settled_time, settled_time))
        assert improving_solutions.read_new_solutions() == [(26.0, solutions[0])]

        for file_path, solution in zip(file_paths[1:], solutions[1:]):
            with open(file_path, "w") as solution_file:
                solution_file.write(solution)
        # the files not read yet are removed too
        assert improving_solutions.file_paths() == file_paths
        # a file is completely written once the next one exists
        assert improving_solutions.read_new_solutions() == [(9.0, solutions[1])]
        assert improving_solutions.read_new_solutions(final=True) == [(2.0, solutions[2])]
        assert improving_solutions.read_new_solutions(final=True) == []
    finally:
        for file_path in file_paths:
            if os.path.exists(file_path):
                os.remove(file_path)


def test_create_progress_log_with_unsupported_solvers():
    milp = MilpXorDifferentialModel(SpeckBlockCipher(number_of_rounds=2))
    search_name = "find_lowest_weight_xor_differential_trail"

    with pytest.raises(ValueError, match="not available for the GLPK/EXACT solver"):
        create_progress_log(milp, search_name, "GLPK/exact", 2, time.time())
    with pytest.raises(ValueError, match="not available for the COIN solver"):
        create_progress_log(milp, search_name, "Coin", 2, time.time())
    with pytest.raises(ValueError, match="not available for the GUROBI solver"):
        create_progress_log(milp, search_name, "Gurobi", 2, time.time())


def test_progress_log_never_writes_a_lower_bound_above_the_bound_of_the_solver():
    milp = MilpXorDifferentialModel(SpeckBlockCipher(number_of_rounds=2))
    progress_log = create_progress_log(milp, "find_lowest_weight_xor_differential_trail", "SCIP_EXT", 2, time.time())
    try:
        progress_log.process_line(" time | node  | dualbound   | primalbound  |  gap   | compl. ")
        # a dual bound reported slightly above the optimum because of the numerical tolerances of the solver
        progress_log.process_line("  1.0s|     1 | 9.000002e+02 | 9.000000e+02 |   0.00%| 100.00%")
        with open(progress_log.file_name) as log_file:
            last_line = log_file.read().splitlines()[-1]
        assert last_line.endswith("| weight >= 9.00 | weight <= 9.00 | gap 0.0% | tree 100.0%")
    finally:
        if os.path.exists(progress_log.file_name):
            os.remove(progress_log.file_name)


def test_glpk_error_messages_are_still_printed():
    milp = MilpXorDifferentialModel(SpeckBlockCipher(number_of_rounds=2))
    progress_log = create_progress_log(milp, "find_lowest_weight_xor_differential_trail", "GLPK", 2, time.time())
    try:
        # a nonzero value prevents GLPK from printing the string
        assert progress_log._receive_glpk_output(None, b"+  1080: mip =     not found yet >=   -inf   (1; 0)\n") == 1
        assert progress_log._receive_glpk_output(None, b"Error detected in file intopt.c at line 42\n") == 0
    finally:
        if os.path.exists(progress_log.file_name):
            os.remove(progress_log.file_name)


def _run_capturing_standard_output(function):
    # the output written to the file descriptor 1, also by C libraries (e.g. GLPK), is captured in a file; the capture
    # fixtures of pytest (capsys, capfd) are not used, since they are not available with pytest-isolate
    sys.stdout.flush()
    with tempfile.TemporaryFile() as captured_output:
        saved_standard_output = os.dup(1)
        os.dup2(captured_output.fileno(), 1)
        try:
            result = function()
            sys.stdout.flush()
        finally:
            os.dup2(saved_standard_output, 1)
            os.close(saved_standard_output)
        captured_output.seek(0)
        return result, captured_output.read().decode(errors="replace")


def test_progress_log_failure_does_not_stop_the_search():
    speck = SpeckBlockCipher(number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    progress_log = create_progress_log(milp, "find_lowest_weight_xor_differential_trail", "SCIP_EXT", 2, time.time())
    log_file_name = progress_log.file_name
    try:
        progress_log.file_name = os.path.join(f"missing_directory_{time.time()}", "file.log")
        scip_header = " time | node  | dualbound   | primalbound  |  gap   | compl. "
        with contextlib.redirect_stdout(io.StringIO()) as output:
            progress_log.process_line(scip_header)
            progress_log.process_line("  1.0s|     1 | 0.000000e+00 | 9.000000e+02 |    Inf | unknown")
        assert "Live logging of the search stopped because of an error" in output.getvalue()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            progress_log.process_line("  2.0s|     2 | 1.000000e+02 | 8.000000e+02 |    Inf | unknown")
            progress_log.write_final({"status": "UNSATISFIABLE"})
        assert output.getvalue() == ""
    finally:
        if os.path.exists(log_file_name):
            os.remove(log_file_name)


def test_format_trail():
    speck = SpeckBlockCipher(number_of_rounds=2)
    differential_values = {
        "plaintext": {"value": "0x00400000"},
        "key": {"value": "0x0"},
        "modadd_0_1": {"value": "0x0"},
        "cipher_output_1_12": {"value": "0x80008002"},
    }
    assert format_trail(speck, differential_values) == "plaintext 0x00400000, key 0x0, cipher_output_1_12 0x80008002"
    linear_values = {
        "plaintext": {"value": "0x00400000"},
        "cipher_output_1_12_i": {"value": "0x1"},
        "cipher_output_1_12_o": {"value": "0x80008002"},
    }
    assert format_trail(speck, linear_values) == "plaintext 0x00400000, cipher_output_1_12_o 0x80008002"


def _read_log_of_lowest_weight_search(search, log_file_name):
    existing_solver_log_file_names = [file_name for file_name in SOLVER_LOG_FILE_NAMES if os.path.exists(file_name)]
    try:
        trail = search()
        with open(log_file_name) as log_file:
            return trail, log_file.read().splitlines()
    finally:
        if os.path.exists(log_file_name):
            os.remove(log_file_name)
        for file_name in SOLVER_LOG_FILE_NAMES:
            if file_name not in existing_solver_log_file_names and os.path.exists(file_name):
                os.remove(file_name)


def test_find_lowest_weight_xor_differential_trail_with_log():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
    plaintext = set_fixed_variables("plaintext", "not_equal", range(32), integer_to_bit_list(0, 32, "little"))
    key = set_fixed_variables("key", "equal", range(64), integer_to_bit_list(0, 64, "little"))
    for solver_name in ["HIGHS_EXT", "SCIP_EXT"]:
        milp = MilpXorDifferentialModel(speck)
        log_file_name = f"{speck.id}__milp_find_lowest_weight_xor_differential_trail__{solver_name}solver.log"
        trail, lines = _read_log_of_lowest_weight_search(
            lambda: milp.find_lowest_weight_xor_differential_trail(
                fixed_values=[plaintext, key], solver_name=solver_name, log=True
            ),
            log_file_name,
        )

        assert round(trail["total_weight"], 2) == 3.0
        assert lines[0].endswith(
            f"| search started: find_lowest_weight_xor_differential_trail, {speck.id}, {solver_name} solver"
        )
        assert lines[-3].endswith("| weight >= 3.00 | weight <= 3.00 | gap 0.0% | OPTIMAL")
        assert lines[-2].endswith("| optimal trail, weight 3.00")
        assert lines[-1].startswith("plaintext 0x")
        assert f", key 0x0000000000000000, {speck.all_components_ids()[-1]} 0x" in lines[-1]
        bounds_lines = [line for line in lines if "| weight >= " in line and "OPTIMAL" not in line]
        assert all(line.count(" | ") == 5 for line in bounds_lines)
        if solver_name == "HIGHS_EXT":
            new_trail_indices = [index for index, line in enumerate(lines) if "| new trail, weight " in line]
            assert new_trail_indices
            assert all(lines[index + 1].startswith("plaintext 0x") for index in new_trail_indices)
        assert not [file_name for file_name in os.listdir() if file_name.endswith(("_improving.sol", "_options.txt"))]


def test_find_lowest_weight_xor_differential_trail_with_log_and_glpk():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    plaintext = set_fixed_variables("plaintext", "not_equal", range(32), integer_to_bit_list(0, 32, "little"))
    key = set_fixed_variables("key", "equal", range(64), integer_to_bit_list(0, 64, "little"))
    for solver_name in ["GLPK", "GLPK_EXT"]:
        milp = MilpXorDifferentialModel(speck)
        log_file_name = f"{speck.id}__milp_find_lowest_weight_xor_differential_trail__{solver_name}solver.log"
        (trail, lines), output = _run_capturing_standard_output(
            lambda: _read_log_of_lowest_weight_search(
                lambda: milp.find_lowest_weight_xor_differential_trail(
                    fixed_values=[plaintext, key], solver_name=solver_name, log=True
                ),
                log_file_name,
            )
        )

        assert trail["total_weight"] == 1.0
        assert lines[0].endswith(
            f"| search started: find_lowest_weight_xor_differential_trail, {speck.id}, {solver_name} solver"
        )
        assert any(" | weight >= " in line and " | tree n/a" in line for line in lines)
        assert lines[-3].endswith("| weight >= 1.00 | weight <= 1.00 | gap 0.0% | OPTIMAL")
        assert lines[-1].startswith("plaintext 0x")
        if solver_name == "GLPK":
            # the output of the GLPK library goes to the log only
            assert "mip =" not in output


@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_lowest_weight_xor_differential_trail_with_log_and_gurobi():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    log_file_name = f"{speck.id}__milp_find_lowest_weight_xor_differential_trail__GUROBI_EXTsolver.log"
    plaintext = set_fixed_variables("plaintext", "not_equal", range(32), integer_to_bit_list(0, 32, "little"))
    key = set_fixed_variables("key", "equal", range(64), integer_to_bit_list(0, 64, "little"))
    trail, lines = _read_log_of_lowest_weight_search(
        lambda: milp.find_lowest_weight_xor_differential_trail(
            fixed_values=[plaintext, key], solver_name="GUROBI_EXT", log=True
        ),
        log_file_name,
    )

    assert trail["total_weight"] == 1.0
    assert lines[0].endswith(
        f"| search started: find_lowest_weight_xor_differential_trail, {speck.id}, GUROBI_EXT solver"
    )
    new_trail_indices = [index for index, line in enumerate(lines) if "| new trail, weight " in line]
    assert new_trail_indices
    assert all(lines[index + 1].startswith("plaintext 0x") for index in new_trail_indices)
    assert lines[-3].endswith("| weight >= 1.00 | weight <= 1.00 | gap 0.0% | OPTIMAL")
    assert lines[-1].startswith("plaintext 0x")
    assert not [file_name for file_name in os.listdir() if "_improving_" in file_name and file_name.endswith(".sol")]


@pytest.mark.skip(reason="Requires CPLEX")
def test_find_lowest_weight_xor_differential_trail_with_log_and_cplex():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    log_file_name = f"{speck.id}__milp_find_lowest_weight_xor_differential_trail__CPLEX_EXTsolver.log"
    plaintext = set_fixed_variables("plaintext", "not_equal", range(32), integer_to_bit_list(0, 32, "little"))
    key = set_fixed_variables("key", "equal", range(64), integer_to_bit_list(0, 64, "little"))
    trail, lines = _read_log_of_lowest_weight_search(
        lambda: milp.find_lowest_weight_xor_differential_trail(
            fixed_values=[plaintext, key], solver_name="CPLEX_EXT", log=True
        ),
        log_file_name,
    )

    assert trail["total_weight"] == 1.0
    assert lines[0].endswith(
        f"| search started: find_lowest_weight_xor_differential_trail, {speck.id}, CPLEX_EXT solver"
    )
    assert any(" | weight >= " in line and " | tree n/a" in line for line in lines)
    assert lines[-3].endswith("| weight >= 1.00 | weight <= 1.00 | gap 0.0% | OPTIMAL")
    assert lines[-1].startswith("plaintext 0x")


def test_find_lowest_weight_xor_linear_trail_with_log():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=4)
    milp = MilpXorLinearModel(speck)
    log_file_name = f"{speck.id}__milp_find_lowest_weight_xor_linear_trail__HIGHS_EXTsolver.log"
    plaintext = set_fixed_variables("plaintext", "not_equal", range(16), integer_to_bit_list(0, 16, "little"))
    trail, lines = _read_log_of_lowest_weight_search(
        lambda: milp.find_lowest_weight_xor_linear_trail(fixed_values=[plaintext], solver_name="HIGHS_EXT", log=True),
        log_file_name,
    )

    weight = f"{trail['total_weight']:.2f}"
    assert lines[-3].endswith(f"| weight >= {weight} | weight <= {weight} | gap 0.0% | OPTIMAL")
    assert lines[-1].startswith("plaintext 0x")
    assert f", {speck.all_components_ids()[-1]}_o 0x" in lines[-1]


def test_find_lowest_weight_trail_with_log_and_unsupported_solver():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpXorDifferentialModel(speck)
    with pytest.raises(ValueError, match="not available for the GLPK/EXACT solver"):
        milp.find_lowest_weight_xor_differential_trail(solver_name="GLPK/exact", log=True)
    assert milp.model is None  # the error is raised before building the model

    milp = MilpXorLinearModel(speck)
    with pytest.raises(ValueError, match="not available for the COIN solver"):
        milp.find_lowest_weight_xor_linear_trail(solver_name="Coin", log=True)
    assert milp.model is None
