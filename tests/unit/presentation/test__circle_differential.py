"""Evidence-only reporting and common probability/weight rendering."""

from io import StringIO

import pytest

from claasp.primitives import BitVectorSBox
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace


@pytest.fixture
def analysis():
    table = (0, 14, 11, 1, 7, 12, 9, 6, 13, 3, 4, 15, 2, 8, 10, 5)
    return BitVectorSBox(4, table).analysis.circle_differential(
        input_name="input", bibrace=BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
    )


def test_reports_reuse_retained_evidence_and_distinguish_sampled_from_exact(analysis, monkeypatch):
    exact = analysis.probability(7, 6)
    sampled = analysis.estimate_probability(7, 6, samples=16, seed=7)
    trail = analysis.best_trail(7)
    sampled_trail = analysis.trail_probability((7, 6), samples=16, seed=7)
    impossible = analysis.trail_probability((7, 0))

    def forbidden(*args, **kwargs):
        raise AssertionError("report repeated execution")

    monkeypatch.setattr(analysis.primitive, "evaluate", forbidden)
    monkeypatch.setattr(analysis.primitive, "evaluate_with_trace", forbidden)
    for result in (exact, sampled, trail, sampled_trail, impossible):
        stream = StringIO()
        result.to_terminal(file=stream)
        text = stream.getvalue()
        assert "Circle-differential" in text
        if result is sampled:
            assert "Confidence interval" in text and "Seed" in text
            assert "Estimated probability" in text
        if result is sampled_trail:
            assert "concrete trail estimate" in text
            assert "Relative estimated conditional probability" in text
            assert "Cumulative estimated probability" in text
            assert "Samples: 16; Seed: 7" in text and "95% confidence interval" in text
        if result is trail:
            assert "Relative conditional probability" in text
            assert "Cumulative probability" in text and "Difference" in text
            assert "Optimal for the fixed input difference" in text
    stream = StringIO()
    trail.to_terminal(details=True, file=stream)
    assert "Hits / ordered pairs" in stream.getvalue()
    assert "concrete" in stream.getvalue()


def test_terminal_needs_no_plotting_dependency(analysis, monkeypatch):
    import builtins

    result = analysis.probability(7, 6)
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.startswith("matplotlib"):
            raise AssertionError("terminal imported matplotlib")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    result.to_terminal(file=StringIO())


def test_plots_save_retained_probabilities_intervals_and_common_weights(
    analysis, monkeypatch, tmp_path
):
    pytest.importorskip("matplotlib").use("Agg")
    from matplotlib import pyplot

    exact = analysis.probability(7, 6)
    sampled = analysis.estimate_probability(7, 6, samples=16)
    trail = analysis.best_trail(7)
    impossible = analysis.trail_probability((7, 0))

    def forbidden(*args, **kwargs):
        raise AssertionError("plot repeated execution")

    monkeypatch.setattr(analysis.primitive, "evaluate", forbidden)
    monkeypatch.setattr(analysis.primitive, "evaluate_with_trace", forbidden)
    try:
        for i, result in enumerate((exact, sampled, trail)):
            path = tmp_path / f"circle-differential-{i}.png"
            artifact = result.plot(show=False, save_to=path)
            assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
            if result is trail:
                assert dict(artifact.series)["cumulative_weight"] == (0.0, 0.0)
                assert artifact.figure.axes[0].get_ylabel() == "Weight (bits)"
            else:
                assert dict(artifact.series)["probability"] == (1.0, 0.0)
                assert artifact.figure.axes[0].get_ylim() == (0.0, 1.0)
        with pytest.raises(ValueError, match="nonzero"):
            impossible.plot(show=False)
    finally:
        pyplot.close("all")
