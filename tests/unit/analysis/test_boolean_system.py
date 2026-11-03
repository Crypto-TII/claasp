from io import StringIO
from subprocess import TimeoutExpired

import pytest

from claasp.analysis import GroebnerResult
from claasp.drivers.algebra import AlgebraExecutionResult, SingularDriver
from claasp.primitives import BitVectorSBox, Speck


def test_round_statistics_and_incidence_graph():
    result = Speck(number_of_rounds=2).analysis.polynomial_system()
    rows = result.statistics()
    separate = result.statistics(cumulative=False)
    assert rows[-1][2] == sum(row[2] for row in separate)
    assert all(row[-1] == 2 for row in rows)
    graph = result.connection_graph(round_number=1)
    assert len(graph.edges) == len(set(graph.edges))
    assert {target for _, target in graph.edges} <= set(graph.equations)
    assert {source for source, _ in graph.edges} == set(graph.variables)
    output = StringIO()
    result.to_terminal(file=output)
    assert "Max degree" in output.getvalue()
    with pytest.raises(ValueError):
        result.connection_graph(round_number=3)


def test_groebner_timeout_is_incomplete(monkeypatch):
    def timeout(*args):
        raise TimeoutExpired("Singular", 0.01)

    monkeypatch.setattr(SingularDriver, "execute", timeout)
    result = (
        BitVectorSBox(2, [0, 1, 3, 2]).analysis.polynomial_system().groebner(timeout_seconds=0.01)
    )
    assert not result.complete and not result.basis
    with pytest.raises(RuntimeError):
        result.require_complete()
    assert GroebnerResult(("1",), True, 0).require_complete().basis == ("1",)


def test_groebner_rejects_missing_completion_marker(monkeypatch):
    monkeypatch.setattr(
        SingularDriver, "execute", lambda *args: AlgebraExecutionResult("partial", "", 0)
    )
    with pytest.raises(RuntimeError, match="complete"):
        BitVectorSBox(2, [0, 1, 3, 2]).analysis.polynomial_system().groebner()
