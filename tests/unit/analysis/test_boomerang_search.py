from subprocess import TimeoutExpired

from claasp.analysis.boomerang_search import BoomerangSearchStatus
from claasp.primitives import ToySpeck


class TimeoutSolver:
    def solve(self, formula):
        raise TimeoutExpired("solver", 1)


def test_timeout_never_claims_unsat_or_optimality():
    analysis = ToySpeck(3).analysis.boomerang(switch_round=1)
    for method in (analysis.find_one_trail, analysis.find_lowest_weight_trail):
        result = method(solver=TimeoutSolver())
        assert result.status is BoomerangSearchStatus.UNKNOWN
        assert result.trail is None
        assert not result.is_optimal
