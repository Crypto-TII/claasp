import pytest

from claasp.analysis import DifferentialLinearSearchResult, ImpossibleSearchResult
from claasp.primitives import ToySpeck


def test_composed_status_never_conflates_unknown_with_exhaustion():
    from enum import Enum

    class Status(Enum):
        UNKNOWN = "unknown"

    class UnknownSolver:
        def solve(self, formula):
            from types import SimpleNamespace

            return SimpleNamespace(status=Status.UNKNOWN, assignment=None, runtime_seconds=0)

    primitive = ToySpeck(3)
    result = primitive.analysis.search_impossible_differentials(solver=UnknownSolver())
    assert not result.complete and not result.found
    with pytest.raises(RuntimeError):
        result.require_complete()
    result = primitive.analysis.find_optimal_differential_linear_trail(solver=UnknownSolver())
    assert not result.complete and not result.found
    with pytest.raises(RuntimeError):
        result.require_complete()


def test_search_validation_precedes_execution():
    primitive = ToySpeck(3)
    for options in (
        {"middle_round": 0},
        {"split_order": (1, 1)},
        {"limit": 0},
        {"representation": "invented"},
    ):
        with pytest.raises(ValueError):
            primitive.analysis.search_impossible_differentials(**options)
    with pytest.raises(ValueError):
        primitive.analysis.find_optimal_differential_linear_trail(prefix_rounds=3)
    assert ImpossibleSearchResult((), (), True, "exhausted UNSAT").require_complete().complete
    assert DifferentialLinearSearchResult(None, None, None, (), True).require_complete().complete
