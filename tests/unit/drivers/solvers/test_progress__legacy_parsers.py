import os
import time

from claasp.drivers.solvers.progress import (
    _CplexProgressParser,
    _GlpkProgressParser,
    _GurobiImprovingSolutions,
    _GurobiProgressParser,
    _HighsImprovingSolutions,
    _HighsProgressParser,
    _ScipProgressParser,
)


def test_cplex_progress_parser():
    parser = _CplexProgressParser()
    assert (
        parser.parse(
            "   Node  Left     Objective  IInf  Best Integer    Best Bound    ItCnt     Gap"
        )
        is None
    )
    assert (
        parser.parse("Elapsed time = 0.05 sec. (54.00 ticks, tree = 0.02 MB, solutions = 0)")
        is None
    )
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
    assert (
        parser.parse(" Expl Unexpl |  Obj  Depth IntInf | Incumbent    BestBd   Gap | It/Node Time")
        is None
    )
    assert (
        parser.parse("Explored 1 nodes (154 simplex iterations) in 0.01 seconds (0.01 work units)")
        is None
    )
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
    row_without_trail = (
        "p 0.1s|     1 |     0 |     0 |     - |shiftand|   0 | 320 |1595 |1579 |   0 |  0 |  16 |"
    )
    row_without_trail += "   0 | 0.000000e+00 |       --     |    Inf | unknown"
    assert parser.parse(row_without_trail) == (0.0, None, None)
    assert parser.parse("SCIP Status        : problem is solved [optimal solution found]") is None


def test_highs_improving_solutions_are_read_incrementally():
    improving_solutions = _HighsImprovingSolutions(f"highs_improving_solutions_test_{time.time()}")
    first_solution = "Objective 3700\n# Columns -2\ny_1 3700\nx_5 1\n"
    second_solution = "Objective 2000\n# Columns -3\ny_1 2000\nx_5 1\nx_7 1\n"
    try:
        assert improving_solutions.solver_command_arguments().startswith(" --options_file ")
        options_file_paths = [
            path for path in improving_solutions.file_paths() if path.endswith("_options.txt")
        ]
        assert len(options_file_paths) == 1
        assert os.path.exists(options_file_paths[0])
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
        f"# Solution for model obj\n# Objective value = {objective}\ny_1 {objective}\n"
        for objective in (26, 9, 2)
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
