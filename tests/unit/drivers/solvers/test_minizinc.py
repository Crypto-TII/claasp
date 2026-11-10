"""CNF execution normalizes CP statuses and preserves native CP contracts."""

from types import SimpleNamespace

import pytest

from claasp.drivers.solvers import CPResult, CPStatus, MiniZincSolver, SatResult, SatStatus
from claasp.representations.constraints.cp import MiniZincModel
from claasp.representations.constraints.sat import CNFFormula


def _output(monkeypatch, stdout):
    monkeypatch.setattr(
        "claasp.drivers.solvers.minizinc.shutil.which", lambda executable: "/fake/minizinc"
    )
    monkeypatch.setattr(
        "claasp.drivers.solvers.minizinc._run_process",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=stdout, stderr=""),
    )


def test_cnf_returns_sat_result_with_checked_logical_names(monkeypatch):
    _output(monkeypatch, '{"v_x": true}\n----------\n')
    formula = CNFFormula(("x",), ((1,),), ("fixed",))
    result = MiniZincSolver().solve(formula)
    assert isinstance(result, SatResult)
    assert result.status is SatStatus.SATISFIABLE and result.assignment == {"x": 1}
    assert formula.is_satisfied(result.assignment)


def test_cnf_unsat_is_a_common_boolean_status(monkeypatch):
    _output(monkeypatch, "=====UNSATISFIABLE=====\n")
    result = MiniZincSolver().solve(CNFFormula(("x",), ((1,), (-1,)), ("one", "zero")))
    assert isinstance(result, SatResult)
    assert result.status is SatStatus.UNSATISFIABLE and result.assignment is None


@pytest.mark.parametrize(
    "stdout", ("=====UNKNOWN=====\n", '{"v_x": true}\n----------\n=====UNKNOWN=====\n')
)
def test_cnf_unknown_never_becomes_an_unsat_proof(monkeypatch, stdout):
    _output(monkeypatch, stdout)
    with pytest.raises(RuntimeError, match="unknown.*not proved"):
        MiniZincSolver().solve(CNFFormula(("x",), ((1,),), ("fixed",)))


@pytest.mark.parametrize(
    "stdout", ("{}\n----------\n", '{"v_x": false}\n----------\n', '{"v_x": 2}\n----------\n')
)
def test_cnf_rejects_incomplete_nonboolean_or_false_witnesses(monkeypatch, stdout):
    _output(monkeypatch, stdout)
    with pytest.raises(RuntimeError, match="assignment"):
        MiniZincSolver().solve(CNFFormula(("x",), ((1,),), ("fixed",)))


def test_native_cp_results_keep_their_native_status_and_values(monkeypatch):
    _output(monkeypatch, '{"x": 3}\n----------\n')
    result = MiniZincSolver().solve(MiniZincModel(("var 0..4: x;",), ("constraint x = 3;",)))
    assert isinstance(result, CPResult)
    assert result.status is CPStatus.SATISFIED and result.values == {"x": 3}
