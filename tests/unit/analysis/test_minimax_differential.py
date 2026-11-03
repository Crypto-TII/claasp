from subprocess import TimeoutExpired

from claasp.primitives import ToySpeck


def test_interrupted_minimax_search_does_not_claim_a_minimum_or_unsat():
    class Interrupted:
        def solve(self, formula):
            raise TimeoutExpired("solver", 1)

    result = ToySpeck(3).analysis.find_minimax_xor_differential_trail(solver=Interrupted())
    assert result.status == "unknown"
    assert not result.is_optimal
    assert result.trail is None
