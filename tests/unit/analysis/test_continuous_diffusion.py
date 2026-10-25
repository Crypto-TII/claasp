"""Numerical contracts for sampled continuous diffusion."""

from io import StringIO
from math import sqrt

import pytest

from claasp.analysis.continuous_diffusion import (
    ContinuousDiffusionResult,
    _boolean_pair,
    _near_pair,
)
from claasp.primitives import ToyAES
from claasp.semantics.cryptanalysis import continuous_sbox

mpmath = pytest.importorskip("mpmath")
numpy = pytest.importorskip("numpy")


def test_pairs_stay_in_domain_and_obey_distance_bound():
    context = mpmath.mp.clone()
    context.dps = 80
    for sampler in (_boolean_pair, _near_pair):
        random = numpy.random.default_rng(9)
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
    random = numpy.random.default_rng(17)
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


def test_per_output_vectors_reproduce_caf_and_detailed_reporting():
    primitive = ToyAES(word_size=3, state_size=3, number_of_rounds=8)
    result = primitive.analysis.continuous_diffusion(seed=9)
    assert len(result.vectors) == 8
    for vector, factor in zip(result.vectors, result.factors, strict=True):
        assert len(vector) == 27
        assert all(0 <= value <= 2 for value in vector)
        assert sum(vector) / len(vector) == pytest.approx(factor)
    output = StringIO()
    result.to_terminal(details=True, file=output)
    assert "CAF contributions — round 8" in output.getvalue()
    assert "Output bit (MSB first)" in output.getvalue()


def test_vector_scores_are_signed_distances_not_boolean_probabilities():
    # Across zero, a signed-distance contribution can be 2, while CAF is
    # the average over output bits. The immutable result must preserve this.
    result = ContinuousDiffusionResult(
        "identity", "state", 0, 0.001, 80, (1,), ((1.0,),), vectors=((0.0, 2.0),)
    )
    assert result.factors == (1.0,)
    assert result.vectors == ((0.0, 2.0),)
    with pytest.raises(ValueError, match="means"):
        ContinuousDiffusionResult(
            "identity", "state", 0, 0.001, 80, (1,), ((0.0,),), vectors=((0.0, 2.0),)
        )
    with pytest.raises(ValueError, match="contributions"):
        ContinuousDiffusionResult(
            "identity", "state", 0, 0.001, 80, (1,), ((0.0,),), vectors=((3.0,),)
        )


def test_measured_vectors_preserve_output_order_sign_reversal_and_zero(monkeypatch):
    from importlib import import_module

    from claasp.primitives.single_component_primitives import Identity

    module = import_module("claasp.analysis.continuous_diffusion")

    def fixed_pair(random, context, width, distance):
        assert width == 3
        return (
            (context.mpf("-.0001"), context.mpf(".0001"), context.mpf(".4")),
            (context.mpf(".0001"), context.mpf("0"), context.mpf(".4")),
        )

    monkeypatch.setattr(module, "_near_pair", fixed_pair)
    result = Identity(3).analysis.continuous_diffusion(
        number_of_samples=1, sampling="uniform_near_pairs"
    )
    assert result.vectors == ((2.0, 1.0, 0.0),)
    assert result.samples == ((1.0,),)
    assert result.factors == (1.0,)


def test_numpy_generator_is_local_recorded_and_prefix_reproducible(monkeypatch):
    primitive = ToyAES(word_size=3, state_size=3, number_of_rounds=2)
    calls = []
    original = numpy.random.default_rng

    def recording_generator(seed):
        generator = original(seed)
        calls.append((seed.state, generator))
        return generator

    monkeypatch.setattr(numpy.random, "default_rng", recording_generator)
    short = primitive.analysis.continuous_diffusion(number_of_samples=3, seed=19)
    long = primitive.analysis.continuous_diffusion(number_of_samples=5, seed=19)
    assert [state for state, _ in calls] == [numpy.random.PCG64(19).state] * 2
    assert all(isinstance(generator, numpy.random.Generator) for _, generator in calls)
    assert short.sampling_engine == long.sampling_engine == "numpy_PCG64"
    assert tuple(row[:3] for row in long.samples) == short.samples
    output = StringIO()
    short.to_terminal(file=output)
    assert "sampling engine" in output.getvalue()
    assert "numpy_PCG64" in output.getvalue()
