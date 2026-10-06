"""Typed phase boundaries retain exact versus sound-truncated claims."""

from dataclasses import replace

import pytest

from claasp.analysis import HybridDifferentialResult, SpeckHybridDifferentialProblem
from claasp.analysis.arx import _find_two_round_speck_xor_differential_bounded
from claasp.primitives import Speck
from claasp.semantics.cryptanalysis import (
    TruncatedXorDifference,
    propagate_two_word_speck_round,
)


def test_exact_prefix_and_sound_suffix_are_independently_checked():
    prefix = _find_two_round_speck_xor_differential_bounded(Speck(number_of_rounds=2)).trail
    primitive = Speck(number_of_rounds=3)
    problem = SpeckHybridDifferentialProblem(
        primitive,
        exact_rounds=2,
        input_difference=prefix.input_pattern.value,
    )
    start = TruncatedXorDifference.parse(f"{prefix.output_pattern.value:032b}")
    end = propagate_two_word_speck_round(primitive, start, 2)
    result = HybridDifferentialResult(prefix, (start, end), 0)
    assert problem.check(result)
    assert not problem.check(replace(result, truncated_boundaries=(start,)))
    assert not hasattr(result, "total_weight")
    assert not hasattr(result, "is_optimal")


@pytest.mark.parametrize("rounds", [0, 3, True, 1.5])
def test_hybrid_requires_both_semantic_phases(rounds):
    with pytest.raises(ValueError):
        SpeckHybridDifferentialProblem(
            Speck(number_of_rounds=3), exact_rounds=rounds, input_difference=1
        )
