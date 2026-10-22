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
    assert result.method == "empirical_paired_evaluation"


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
    assert "[0.49, 0.51]" in text and "tolerance" in text and "0.01" in text
    assert "positions" not in text
    assert "not met" in text
    assert "Input bit |" not in text
    result.to_terminal(details=True, metric="entropy")
    details = capsys.readouterr().out
    assert "Min positions" in details and "Max positions" in details
    assert "avalanche_entropy" in details
    assert "[0.99, 1]" in details
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
