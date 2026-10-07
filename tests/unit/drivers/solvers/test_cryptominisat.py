import pytest

from claasp.drivers.solvers import CryptoMiniSatSolver, SatStatus
from claasp.representations.constraints.sat import NativeXorCNFFormula


def test_cryptominisat_result_parser_maps_dimacs_literals_to_names():
    text = "s SATISFIABLE\nv 1 -2 0\n"
    status, assignment = CryptoMiniSatSolver._parse_result(text, ("x", "y"))
    assert status is SatStatus.SATISFIABLE
    assert assignment == {"x": 1, "y": 0}


def test_cryptominisat_result_parser_handles_unsatisfiable_result():
    assert CryptoMiniSatSolver._parse_result("s UNSATISFIABLE\n", ("x",)) == (
        SatStatus.UNSATISFIABLE,
        None,
    )


def test_cryptominisat_result_parser_rejects_malformed_or_incomplete_results():
    with pytest.raises(RuntimeError, match="unrecognized"):
        CryptoMiniSatSolver._parse_result("s UNKNOWN\n", ("x",))
    with pytest.raises(RuntimeError, match="incomplete"):
        CryptoMiniSatSolver._parse_result("s SATISFIABLE\nv 1 0\n", ("x", "y"))


def test_cryptominisat_validates_executable_timeout_and_assumptions():
    formula = NativeXorCNFFormula(("x",), (), (), (), ((1,),), ("parity",))
    with pytest.raises(ValueError, match="positive"):
        CryptoMiniSatSolver(timeout_seconds=0)
    with pytest.raises(FileNotFoundError, match="was not found"):
        CryptoMiniSatSolver("definitely-not-a-sat-solver").solve(formula)
    with pytest.raises(ValueError, match="unknown variable"):
        CryptoMiniSatSolver._assumption_clauses(formula, {"y": 1})
    with pytest.raises(ValueError, match="must be Boolean"):
        CryptoMiniSatSolver._assumption_clauses(formula, {"x": 2})


def test_cryptominisat_preserves_native_xor_when_adding_assumptions():
    formula = NativeXorCNFFormula(("a", "b"), (), (), (), ((1, -2),), ("parity",))
    augmented = CryptoMiniSatSolver._with_assumptions(formula, ((1,),))
    assert isinstance(augmented, NativeXorCNFFormula)
    assert augmented.clauses == ((1,),)
    assert augmented.xor_clauses == formula.xor_clauses
