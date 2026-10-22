"""Numerical contracts for sampled continuous diffusion."""

from io import StringIO
from math import sqrt
from random import Random

import pytest

from claasp.analysis.continuous_diffusion import (
    ContinuousDiffusionResult,
    _boolean_pair,
    _near_pair,
)
from claasp.primitives import ToyAES
from claasp.semantics.cryptanalysis import continuous_sbox

mpmath = pytest.importorskip("mpmath")


def test_pairs_stay_in_domain_and_obey_distance_bound():
    context = mpmath.mp.clone()
    context.dps = 80
    for sampler in (_boolean_pair, _near_pair):
        random = Random(9)
        for _ in range(20):
            left, right = sampler(random, context, 27, 0.001)
            assert all(-1 <= value <= 1 for value in (*left, *right))
            distance = sqrt(float(sum((a - b) ** 2 for a, b in zip(left, right))))
            assert distance <= 0.001 * (1 + 1e-12)
            if sampler is _boolean_pair:
                assert sum(a != b for a, b in zip(left, right)) == 1
                assert all(abs(value) == 1 for value in left)


def test_uniform_pairs_include_overlap_volume_weighting():
    context = mpmath.mp.clone()
    context.dps = 30
    random = Random(17)
    points = [_near_pair(random, context, 1, 1) for _ in range(4000)]
    # Exact area calculation: the diagonal strip has area 3 and its
    # part with first coordinate > 1/2 has area 5/8.
    observed = sum(left[0] > 0.5 for left, _ in points) / len(points)
    assert observed == pytest.approx(5 / 24, abs=0.025)


def test_walsh_evaluation_agrees_with_independent_probability_enumeration():
    values = (0.12, -0.32, 0.75)
    table = (0, 1, 5, 6, 7, 2, 3, 4)
    expected = []
    for shift in (2, 1, 0):
        mean = 0.0
        for x, y in enumerate(table):
            probability = 1.0
            for bit, correlation in enumerate(values):
                sign = 1 if (x >> (2 - bit)) & 1 else -1
                probability *= (1 + sign * correlation) / 2
            mean += probability * (1 if (y >> shift) & 1 else -1)
        expected.append(mean)
    assert continuous_sbox(values, table) == pytest.approx(expected)


def test_walsh_evaluation_preserves_tiny_correlations():
    context = mpmath.mp.clone()
    context.dps = 80
    values = (context.mpf("1e-1000"), context.mpf("-1e-2000"))
    assert continuous_sbox(values, (0, 1, 2, 3)) == values


def test_default_experiment_is_reproducible_precision_local_and_round_labelled():
    primitive = ToyAES(word_size=3, state_size=3, number_of_rounds=8)
    before = mpmath.mp.dps
    result = primitive.analysis.continuous_diffusion(seed=9)
    higher = primitive.analysis.continuous_diffusion(seed=9, precision=120)
    assert mpmath.mp.dps == before
    assert result.samples == higher.samples
    assert result.round_numbers == tuple(range(1, 9))
    assert len(result.samples[0]) == 16
    assert result.method == "boolean_neighborhood"
    assert result.factors[:4] == (0, 0, 0, 0)
    assert any(value > 0.5 for value in result.factors[5:])
    assert result.claim_kind == "heuristic"


@pytest.mark.parametrize(
    "options",
    [
        {"number_of_samples": 0},
        {"number_of_samples": True},
        {"lambda_value": 0},
        {"lambda_value": float("nan")},
        {"precision": 10},
        {"precision": True},
        {"seed": True},
        {"sampling": "unknown"},
    ],
)
def test_bad_settings_fail_before_execution(options):
    with pytest.raises(ValueError):
        ToyAES(word_size=3, state_size=3, number_of_rounds=1).analysis.continuous_diffusion(
            **options
        )


def test_report_accepts_caf_above_one_and_does_not_repeat_measurement(monkeypatch, capsys):
    result = ContinuousDiffusionResult("test", "state", 9, 0.001, 80, (1,), ((1.5, 1.25),))
    monkeypatch.setattr(
        ToyAES, "evaluate", lambda *args, **kwargs: pytest.fail("repeated evaluation")
    )
    result.to_terminal()
    printed = capsys.readouterr().out
    output = StringIO()
    result.to_terminal(file=output)
    assert output.getvalue() == printed
    assert "1.375" in printed and "heuristic" in printed
