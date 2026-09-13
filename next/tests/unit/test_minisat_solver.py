import pytest

from claasp_next.representations.constraints.sat import CNFFormula
from claasp_next.drivers.solvers import MinisatSolver, SatStatus


def test_minisat_result_parser_maps_dimacs_literals_to_names():
    status, assignment = MinisatSolver._parse_result("SAT\n1 -2 0\n", ("x", "y"))
    assert status is SatStatus.SATISFIABLE
    assert assignment == {"x": 1, "y": 0}


def test_minisat_result_parser_handles_unsatisfiable_result():
    assert MinisatSolver._parse_result("UNSAT\n", ("x",)) == (
        SatStatus.UNSATISFIABLE,
        None,
    )


def test_minisat_result_parser_rejects_malformed_or_incomplete_results():
    with pytest.raises(RuntimeError, match="unrecognized"):
        MinisatSolver._parse_result("UNKNOWN\n", ("x",))
    with pytest.raises(RuntimeError, match="incomplete"):
        MinisatSolver._parse_result("SAT\n1 0\n", ("x", "y"))


def test_minisat_validates_executable_timeout_and_assumptions():
    formula = CNFFormula(("x",), ((1,),), ("fixed",))
    with pytest.raises(ValueError, match="positive"):
        MinisatSolver(timeout_seconds=0)
    with pytest.raises(FileNotFoundError, match="was not found"):
        MinisatSolver("definitely-not-a-sat-solver").solve(formula)
    with pytest.raises(ValueError, match="unknown variable"):
        MinisatSolver._assumption_clauses(formula, {"y": 1})
    with pytest.raises(ValueError, match="must be Boolean"):
        MinisatSolver._assumption_clauses(formula, {"x": 2})


def test_sat_result_convenience_property():
    from claasp_next.drivers.solvers import SatResult

    result = SatResult(SatStatus.SATISFIABLE, {"x": 1}, 0.01, "", "")
    assert result.is_satisfiable
