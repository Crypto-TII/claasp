"""User-facing fixed/bounded characteristic queries use the real Z3 driver."""

import doctest
from io import StringIO
from subprocess import TimeoutExpired
from types import SimpleNamespace

import pytest

from claasp.analysis import Analysis
from claasp.drivers.solvers import Z3Solver
from claasp.primitives import Heys, ToySpeck
from claasp.representations.constraints.smt import (
    WordXorDifferentialSMTModel,
    WordXorLinearSMTModel,
)

pytestmark = pytest.mark.external


class OneCallSolver:
    def __init__(self):
        self.calls = 0

    def solve(self, formula):
        self.calls += 1
        assert self.calls == 1, "a one-trail query must not enumerate or prove an optimum"
        return Z3Solver(timeout_seconds=10).solve(formula)


@pytest.mark.parametrize("kind", ["differential", "linear"])
def test_find_one_returns_a_checked_characteristic_after_exactly_one_solver_call(kind):
    primitive = ToySpeck(2)
    driver = OneCallSolver()
    trail = getattr(primitive.analysis, f"find_one_xor_{kind}_trail")(1, solver=driver)
    assert trail is not None and trail.total_weight <= 1 and driver.calls == 1
    model = (
        WordXorDifferentialSMTModel(
            primitive,
            maximum_weight=1,
            nonzero_input="plaintext",
            fixed_input_differences={"key": 0},
        )
        if kind == "differential"
        else WordXorLinearSMTModel(
            primitive, maximum_weight=1, nonzero_input="plaintext", fixed_inputs={"key": 0}
        )
    )
    model.smt_formula()
    assert model.check_characteristic(trail)
    stream = StringIO()
    trail.to_terminal(details=True, file=stream)
    assert "Component transitions" in stream.getvalue()


@pytest.mark.parametrize("kind", ["differential", "linear"])
def test_fixed_weight_and_bounded_queries_preserve_constraints_and_completion(kind, monkeypatch):
    analysis = ToySpeck(2).analysis
    one = getattr(analysis, f"find_one_xor_{kind}_trail_with_fixed_weight")(1)
    assert one is not None and one.total_weight == 1
    result = getattr(analysis, f"find_all_xor_{kind}_trails_with_weight_at_most")(1, limit=200)
    assert result.require_complete() is result
    assert all(trail.total_weight <= 1 for trail in result.trails)
    assert len(result.trails) == (7 if kind == "differential" else 99)
    output = StringIO()
    result.to_terminal(file=output)
    assert "Complete enumeration" in output.getvalue()
    limited = getattr(analysis, f"find_all_xor_{kind}_trails_with_weight_at_most")(1, limit=1)
    assert not limited.complete and len(limited.trails) == 1

    def forbidden(*args, **kwargs):
        raise AssertionError("terminal reporting must reuse retained results")

    monkeypatch.setattr(Z3Solver, "solve", forbidden)
    output = StringIO()
    limited.to_terminal(file=output)
    assert "Incomplete enumeration" in output.getvalue()
    with pytest.raises(RuntimeError, match="incomplete"):
        limited.require_complete()


@pytest.mark.parametrize("kind,weight", [("differential", 1.415), ("linear", 0.415)])
def test_fractional_one_trail_query_reuses_exact_probability_interval_checks(kind, weight):
    options = (
        {"fixed_input_differences": {"plaintext": 0x2000, "key": 0}, "output_difference": 0x5000}
        if kind == "differential"
        else {}
    )
    trail = getattr(
        Heys(number_of_rounds=1).analysis, f"find_one_xor_{kind}_trail_with_fixed_weight"
    )(weight, weight_tolerance=0.001, **options)
    assert trail is not None and weight - 0.001 <= trail.total_weight <= weight + 0.001
    if kind == "differential":
        assert dict(trail.input_differences)["plaintext"] == 0x2000
        assert trail.output_difference == 0x5000


@pytest.mark.parametrize("kind", ["differential", "linear"])
def test_proved_unsatisfiability_is_none_and_empty_enumeration_is_reportable(kind):
    analysis = ToySpeck(1).analysis
    assert getattr(analysis, f"find_one_xor_{kind}_trail_with_fixed_weight")(100) is None
    result = getattr(analysis, f"find_all_xor_{kind}_trails_with_weight_at_most")(
        101, minimum_weight=100
    )
    assert result.complete and not result.trails
    output = StringIO()
    result.to_terminal(file=output)
    assert "No characteristics satisfy the query" in output.getvalue()


def test_solver_interruption_does_not_mean_proved_unsatisfiability():
    class TimeoutSolver:
        def solve(self, formula):
            raise TimeoutExpired("test", 1)

    class UnknownSolver:
        def solve(self, formula):
            return SimpleNamespace(status="unknown", assignment=None)

    for kind in ("differential", "linear"):
        method = getattr(ToySpeck(1).analysis, f"find_one_xor_{kind}_trail")
        with pytest.raises(TimeoutExpired):
            method(solver=TimeoutSolver())
        with pytest.raises(RuntimeError, match="did not complete"):
            method(solver=UnknownSolver())


def test_new_api_doctests_are_executable_with_the_optional_solver():
    import claasp.analysis.facade as module

    runner = doctest.DocTestRunner()
    for kind in ("differential", "linear"):
        names = (
            f"find_one_xor_{kind}_trail",
            f"find_one_xor_{kind}_trail_with_fixed_weight",
            f"find_all_xor_{kind}_trails_with_weight_at_most",
        )
        for name in names:
            method = getattr(Analysis, name)
            assert method.__doc__ is not None
            test = doctest.DocTestParser().get_doctest(
                method.__doc__, vars(module).copy(), method.__qualname__, module.__file__, 0
            )
            assert test.examples
            runner.run(test)
    assert runner.summarize().failed == 0
