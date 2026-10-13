import pytest

from claasp.drivers.solvers import KissatSolver, SatStatus
from claasp.representations.constraints.sat import CNFFormula


def test_kissat_result_parser_maps_dimacs_literals_to_names():
    text = "s SATISFIABLE\nv 1 -2 0\n"
    status, assignment = KissatSolver._parse_result(text, ("x", "y"))
    assert status is SatStatus.SATISFIABLE
    assert assignment == {"x": 1, "y": 0}


def test_kissat_result_parser_handles_unsatisfiable_result():
    assert KissatSolver._parse_result("s UNSATISFIABLE\n", ("x",)) == (
        SatStatus.UNSATISFIABLE,
        None,
    )


def test_kissat_result_parser_rejects_malformed_or_incomplete_results():
    with pytest.raises(RuntimeError, match="unrecognized"):
        KissatSolver._parse_result("s UNKNOWN\n", ("x",))
    with pytest.raises(RuntimeError, match="incomplete"):
        KissatSolver._parse_result("s SATISFIABLE\nv 1 0\n", ("x", "y"))


def test_kissat_validates_executable_timeout_and_assumptions():
    formula = CNFFormula(("x",), ((1,),), ("fixed",))
    with pytest.raises(ValueError, match="positive"):
        KissatSolver(timeout_seconds=0)
    with pytest.raises(FileNotFoundError, match="was not found"):
        KissatSolver("definitely-not-a-sat-solver").solve(formula)
    with pytest.raises(ValueError, match="unknown variable"):
        KissatSolver._assumption_clauses(formula, {"y": 1})
    with pytest.raises(ValueError, match="must be Boolean"):
        KissatSolver._assumption_clauses(formula, {"x": 2})


def test_kissat_parses_peak_memory_and_corrects_darwin_units():
    output = "c maximum-resident-set-size:       3732930560 bytes       3560 MB\n"
    assert KissatSolver._parse_peak_memory(output, "linux") == 3732930560
    assert KissatSolver._parse_peak_memory(output, "darwin") == 3645440
