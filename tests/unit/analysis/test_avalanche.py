import pytest

from claasp.analysis.avalanche import avalanche_probabilities
from claasp.primitives import Speck


def test_one_round_speck_avalanche_fixture_is_reproducible():
    primitive = Speck(number_of_rounds=1)
    result = avalanche_probabilities(primitive, "plaintext", 4, seed=9, fixed_inputs={"key": 0})

    assert result.input_bit_count == 32
    assert result.output_bit_count == 32
    assert result.probabilities[0] == (
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.5,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.5,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
    )
    assert result.complete is False
    assert result.method == "numpy_paired_evaluation"


def test_avalanche_summary_and_input_validation():
    primitive = Speck(number_of_rounds=1)
    result = avalanche_probabilities(primitive, "plaintext", 2, seed=0)

    assert result.mean_changed_output_bits[0] == sum(result.probabilities[0])
    assert 0 <= result.maximum_sac_bias <= 0.5
    with pytest.raises(KeyError, match="nonce"):
        avalanche_probabilities(primitive, "nonce", 1)


def test_primitive_analysis_facade_exposes_avalanche():
    result = Speck(number_of_rounds=1).analysis.avalanche(
        "plaintext", 2, seed=9, fixed_inputs={"key": 0}
    )
    assert result.sample_count == 2
    assert result.input_name == "plaintext"


def test_terminal_report_uses_current_stdout_or_explicit_stream(capsys):
    from io import StringIO

    from claasp.analysis.avalanche import AvalancheResult
    from claasp.presentation import avalanche_section, render_section

    result = AvalancheResult("fixture", "plaintext", 2, 9, ((0.0, 0.5), (1.0, 0.5)))
    expected = render_section(avalanche_section(result), format="terminal")
    result.to_terminal()
    assert capsys.readouterr().out == expected
    output = StringIO()
    result.to_terminal(file=output)
    assert output.getvalue() == expected
    assert capsys.readouterr().out == ""


def test_result_terminal_output_does_not_import_optional_dependencies():
    import os
    import subprocess
    import sys

    environment = {**os.environ, "PYTHONPATH": "src"}
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from io import StringIO; "
            "from claasp.analysis.avalanche import AvalancheResult; "
            "AvalancheResult('example', 'plaintext', 2, 9, ((0.5,),)).to_terminal(file=StringIO()); "
            "assert not any(name in sys.modules for name in "
            "('matplotlib', 'numpy', 'pandas', 'tensorflow'))",
        ],
        env=environment,
        check=True,
    )


def test_retained_rounds_match_independent_prefix_evaluations():
    from random import Random

    result = Speck(number_of_rounds=3).analysis.avalanche("plaintext", 4, seed=9)
    assert result.round_numbers == (1, 2, 3)
    for rounds, matrix in zip(result.round_numbers, result.round_probabilities, strict=True):
        primitive = Speck(number_of_rounds=rounds)
        random = Random(9)
        inputs = [(random.getrandbits(32), random.getrandbits(64)) for _ in range(4)]
        expected = []
        for bit in range(32):
            differences = []
            for plaintext, key in inputs:
                baseline = primitive.evaluate(plaintext, key)
                changed = primitive.evaluate(plaintext ^ (1 << (31 - bit)), key)
                assert isinstance(baseline, int) and isinstance(changed, int)
                differences.append(baseline ^ changed)
            expected.append(
                tuple(sum((d >> (31 - b)) & 1 for d in differences) / 4 for b in range(32))
            )
        assert matrix == tuple(expected)
    assert result.probabilities == result.round_probabilities[-1]


def test_statistics_entropy_and_exact_threshold_boundaries():
    from claasp.analysis.avalanche import (
        AvalancheResult,
        _metric_matrix,
        _round_profiles,
        _round_statistics,
    )

    first = ((0.0, 0.5), (1.0, 0.5))
    final = ((0.25, 0.5), (0.75, 0.5))
    result = AvalancheResult(
        "fixture",
        "plaintext",
        4,
        9,
        final,
        round_probabilities=(first, final),
        round_numbers=(1, 2),
        threshold=0.25,
    )
    rows = _round_statistics(result, "probability")
    assert (rows[0].minimum, rows[0].maximum, rows[0].average) == (0.0, 1.0, 0.5)
    assert rows[0].minimum_positions == ((0, 0),)
    assert rows[0].maximum_positions == ((1, 0),)
    assert not rows[0].satisfied
    assert rows[1].satisfied
    assert _metric_matrix(first, "entropy") == ((0.0, 1.0), (0.0, 1.0))
    assert _round_profiles(result, "entropy")[0] == (0.0, 1.0)
    assert _round_profiles(result, "probability")[0] == (0.5, 0.5)
    assert _round_profiles(result, "weight") == _round_profiles(result, "probability")
    assert not _round_statistics(result, "entropy")[0].satisfied


def test_terminal_basic_and_detailed_reports(capsys):
    result = Speck(number_of_rounds=2).analysis.avalanche("plaintext", 2, seed=9)
    result.to_terminal()
    text = capsys.readouterr().out
    assert "avalanche_probability" in text
    assert "maximum SAC bias (final round 2)" in text
    assert "[0, 1]" in text and "simultaneous confidence" in text and "95.0%" in text
    assert "positions" not in text
    assert "inconclusive" in text
    assert "Input bit |" not in text
    result.to_terminal(details=True, metric="entropy")
    details = capsys.readouterr().out
    assert "Min positions" in details and "Max positions" in details
    assert "avalanche_entropy" in details
    assert "[0, 1]" in details
    assert "Empirical avalanche entropy — round 1" in details
    assert "Empirical avalanche entropy — round 2" in details
    assert "Output 31" in details


@pytest.mark.parametrize("metric", ["entropy", "probability", "weight"])
def test_selectable_analysis_metrics(metric):
    result = Speck(number_of_rounds=1).analysis.avalanche(
        "plaintext", 2, metric=metric, threshold=0.1
    )
    assert result.metric == metric
    assert result.threshold == 0.1


@pytest.mark.parametrize("threshold", [-1, float("nan"), float("inf"), True, 1.1])
def test_invalid_threshold_rejected_before_evaluation(threshold):
    with pytest.raises(ValueError, match="threshold"):
        Speck(number_of_rounds=1).analysis.avalanche("plaintext", 2, threshold=threshold)


def test_invalid_metric_and_round_metadata_are_rejected():
    from claasp.analysis.avalanche import AvalancheResult

    with pytest.raises(ValueError, match="metric"):
        Speck(number_of_rounds=1).analysis.avalanche("plaintext", 2, metric="unknown")
    with pytest.raises(ValueError, match="supplied together"):
        AvalancheResult("fixture", "input", 2, 9, ((0.5,),), round_numbers=(1,))
    with pytest.raises(ValueError, match="final round"):
        AvalancheResult(
            "fixture",
            "input",
            2,
            9,
            ((0.5,),),
            round_numbers=(1,),
            round_probabilities=(((0.0,),),),
        )


def test_sparse_round_publications_keep_original_round_numbers():
    from claasp import BitWord, PrimitiveBuilder
    from claasp.components import Xor

    builder = PrimitiveBuilder("sparse", kind="permutation")
    (state,) = builder.set_inputs(state=BitWord(2))
    for number in range(3):
        builder.add_round()
        state = builder.add(Xor(state, state))
        if number == 1:
            builder.set_round_output(state)
    builder.set_output(state)
    primitive = builder.build()
    assert tuple(number for number, _ in primitive.graph.round_output_boundaries) == (1,)
    result = primitive.analysis.avalanche("state", 2)
    assert result.round_numbers == (2, 3)
    assert len(result.round_probabilities) == 2


def test_zero_round_primitive_does_not_invent_a_round_number():
    from claasp import BitWord, PrimitiveBuilder

    builder = PrimitiveBuilder("identity", kind="permutation")
    (state,) = builder.set_inputs(state=BitWord(2))
    builder.set_output(state)
    result = builder.build().analysis.avalanche("state", 1)
    assert result.round_numbers == ()
    assert result.probabilities == ((1.0, 0.0), (0.0, 1.0))


def test_final_aes_matrix_matches_the_dataset_contract():
    from claasp.analysis.datasets import generate_avalanche_dataset
    from claasp.primitives import AES

    primitive = AES(number_of_rounds=2)
    result = primitive.analysis.avalanche("plaintext", 1, seed=7, fixed_inputs={"key": 0})
    dataset = generate_avalanche_dataset(primitive, "plaintext", 1, seed=7, fixed_inputs={"key": 0})
    expected = tuple(
        tuple(float((record.output_difference >> (127 - bit)) & 1) for bit in range(128))
        for record in dataset.records
    )
    assert result.probabilities == expected
    assert result.round_numbers == (1, 2)


@pytest.mark.parametrize(
    "family,samples", [("speck", 3), ("speck", 257), ("chacha", 3), ("aes", 3)]
)
def test_numpy_and_scalar_match_round_vectors(family, samples):
    from claasp.primitives import AES, ChaChaPermutation

    primitive = {"speck": Speck, "chacha": ChaChaPermutation, "aes": AES}[family](
        number_of_rounds=1
    )
    reference = primitive.analysis.avalanche(number_of_samples=samples, seed=19, engine="scalar")
    actual = primitive.analysis.avalanche(number_of_samples=samples, seed=19)
    assert actual.round_probabilities == reference.round_probabilities
    assert actual.probabilities == reference.probabilities
    assert actual.method == (
        "numpy_hybrid_paired_evaluation" if family == "aes" else "numpy_paired_evaluation"
    )


def test_derived_metrics_and_criteria_do_not_hide_biased_pairs():
    from claasp.analysis.avalanche import AvalancheResult

    biased = ((0.0, 1.0), (1.0, 0.0))
    ideal = ((0.5, 0.5), (0.5, 0.5))
    result = AvalancheResult(
        "demo", "state", 2, 0, ideal, round_probabilities=(biased, ideal), round_numbers=(1, 2)
    )
    assert result.dependence() == ((1.0, 1.0), (2.0, 2.0))
    assert result.weight() == ((1.0, 1.0), (1.0, 1.0))
    assert result.entropy() == ((0.0, 0.0), (2.0, 2.0))
    checks = result.check_criteria()
    assert [c["full_diffusion"] for c in checks] == [False, True]
    assert [c["avalanche"] for c in checks] == [True, True]
    assert [c["strict_avalanche"] for c in checks] == [False, True]
    for keyword in ("dependence_threshold", "weight_threshold", "entropy_threshold"):
        for invalid in (-1, float("nan"), True):
            with pytest.raises(ValueError, match="tolerances"):
                result.check_criteria(**{keyword: invalid})


def test_numpy_engine_does_not_evaluate_samples_with_scalar_driver(monkeypatch):
    from claasp.representations.execution.scalar import ScalarExecutionDriver

    def forbidden(*args, **kwargs):
        raise AssertionError("scalar sample evaluation used")

    monkeypatch.setattr(ScalarExecutionDriver, "evaluate", forbidden)
    result = Speck(number_of_rounds=2).analysis.avalanche(number_of_samples=8)
    assert result.method == "numpy_paired_evaluation"


def test_explicit_numpy_dependency_error_and_scalar_alternative(monkeypatch):
    import builtins

    original = builtins.__import__

    def without_numpy(name, *args, **kwargs):
        if name == "numpy":
            raise ImportError("deliberately unavailable")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_numpy)
    primitive = Speck(number_of_rounds=1)
    with pytest.raises(ImportError, match="analysis"):
        primitive.analysis.avalanche(number_of_samples=1)
    assert (
        primitive.analysis.avalanche(number_of_samples=1, engine="scalar").method
        == "scalar_paired_evaluation"
    )


def test_sample_dependent_band_scales_with_samples_and_comparisons():
    from dataclasses import replace
    from math import log, sqrt

    from claasp.analysis.avalanche import AvalancheResult, _report_bounds

    result = AvalancheResult("fixture", "state", 1000, 0, ((0.5, 0.5),) * 2)
    low, high = _report_bounds(result, "probability")
    radius = sqrt(log(2 * 4 / 0.05) / (2 * 1000))
    assert low == pytest.approx(0.5 - radius)
    assert high == pytest.approx(0.5 + radius)
    # Four times the independent samples halve the radius.
    assert _report_bounds(replace(result, sample_count=4000), "probability")[
        1
    ] - 0.5 == pytest.approx(radius / 2)
    # More comparisons, including across rounds, widen the simultaneous band.
    more_pairs = replace(result, probabilities=((0.5, 0.5),) * 4)
    assert _report_bounds(more_pairs, "probability")[1] > high
    more_rounds = replace(
        result, round_probabilities=(result.probabilities,) * 2, round_numbers=(1, 2)
    )
    assert (
        _report_bounds(more_rounds, "probability")[1]
        == _report_bounds(more_pairs, "probability")[1]
    )
    assert _report_bounds(replace(result, confidence=0.99), "probability")[1] > high


def test_speck_default_sac_check_detects_early_rounds_and_accepts_seventh(capsys):
    from claasp.analysis.avalanche import _round_statistics

    result = Speck(number_of_rounds=7).analysis.avalanche()
    probability = _round_statistics(result, "probability")
    entropy = _round_statistics(result, "entropy")
    assert [row.satisfied for row in probability] == [False] * 6 + [True]
    assert [row.satisfied for row in entropy] == [row.satisfied for row in probability]
    result.to_terminal()
    report = capsys.readouterr().out
    assert "95.0%" in report and "7168 pairs across all retained rounds" in report
    assert report.count("deviation detected") == 6
    assert "consistent" in report


@pytest.mark.parametrize("confidence", [0, 1, -0.1, 1.1, float("nan"), float("inf"), True])
def test_invalid_confidence_rejected_before_evaluation(confidence):
    with pytest.raises(ValueError, match="confidence"):
        Speck(number_of_rounds=1).analysis.avalanche(number_of_samples=1, confidence=confidence)


def test_fixed_tolerance_override_is_explicit_in_terminal(capsys):
    result = Speck(number_of_rounds=1).analysis.avalanche(number_of_samples=2, threshold=0.01)
    result.to_terminal()
    text = capsys.readouterr().out
    assert "Tolerance check" in text and "fixed tolerance" in text
    assert "[0.49, 0.51]" in text
    assert "simultaneous confidence" not in text


def test_no_sampling_power_is_reported_as_inconclusive(capsys):
    from claasp.analysis.avalanche import AvalancheResult

    result = AvalancheResult("fixture", "state", 1, 0, ((0.0, 1.0),))
    result.to_terminal()
    assert "inconclusive" in capsys.readouterr().out
    result.to_terminal(metric="dependence")
    text = capsys.readouterr().out
    assert "Observed diffusion" in text and "missing flips" in text
    assert "SAC check" not in text


def test_statistical_band_respects_exact_binomial_false_detection_budget():
    from math import comb

    from claasp.analysis.avalanche import AvalancheResult, _comparison_count, _report_bounds

    result = AvalancheResult("fixture", "state", 100, 0, ((0.5, 0.5),) * 2)
    lower, upper = _report_bounds(result, "probability")
    # Independently enumerate the binomial distribution under an ideal pair,
    # rather than simulating a noisy test or assuming pairs are independent.
    false_detection = sum(
        comb(100, successes) / 2**100
        for successes in range(101)
        if not lower <= successes / 100 <= upper
    )
    assert _comparison_count(result) * false_detection <= 1 - result.confidence
