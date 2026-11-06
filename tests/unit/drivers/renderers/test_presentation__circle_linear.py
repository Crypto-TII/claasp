"""Rendered series use retained mathematical evidence and standard figure controls."""

from fractions import Fraction
from typing import Any, cast

import pytest

from claasp.analysis.circle_linear import CircleApproximation, CircleCorrelationEstimate
from claasp.primitives import Craft
from claasp.semantics.cryptanalysis.circle_linear import CircleTrail

matplotlib = pytest.importorskip("matplotlib")
matplotlib.use("Agg")
pyplot = pytest.importorskip("matplotlib.pyplot")


def test_subgroup_weight_plot_matches_round_costs_and_never_researches(tmp_path, monkeypatch):
    model = Craft(number_of_rounds=8).circle_linear_trail_model()
    result = model.search()
    monkeypatch.setattr(type(model), "search", lambda *a, **k: pytest.fail("search repeated"))
    monkeypatch.setattr(pyplot, "show", lambda: pytest.fail("show=False ignored"))
    destination = tmp_path / "circle trail.png"
    artifact = result.plot(show=False, save_to=destination)
    series = dict(artifact.series)
    assert series["relative_weight"] == (0, 0, 4, 0, 2, 0, 0, 0, 2)
    assert series["cumulative_weight"][-1] == result.cost
    assert (
        tuple(cast(Any, artifact.figure).axes[0].lines[0].get_ydata()) == series["relative_weight"]
    )
    assert "not endpoint correlation" in cast(Any, artifact.figure).axes[0].get_title()
    assert destination.stat().st_size > 100
    pyplot.close(artifact.figure)
    selected = result.representative.plot(show=False)
    assert selected.series == artifact.series
    pyplot.close(selected.figure)


def test_exact_endpoint_plot_converts_signed_correlation_to_probabilities():
    artifact = CircleApproximation(7, 14, Fraction(-1)).plot(show=False)
    assert dict(artifact.series)["probability"] == (0, 1)
    assert [p.get_height() for p in cast(Any, artifact.figure).axes[0].patches] == [0, 1]
    assert "Exact" in cast(Any, artifact.figure).axes[0].get_title()
    pyplot.close(artifact.figure)


def test_estimate_plot_retains_confidence_interval_and_show_option(monkeypatch):
    calls = []
    monkeypatch.setattr(pyplot, "show", lambda: calls.append(True))
    estimate = CircleCorrelationEstimate(0.5, 100, 7, 0.05, 0.2, 0.8, 0.95)
    artifact = estimate.plot()
    series = dict(artifact.series)
    assert series["probability"] == (0.75, 0.25)
    assert series["lower"] == pytest.approx((0.6, 0.1))
    assert series["upper"] == pytest.approx((0.9, 0.4))
    assert "95%" in cast(Any, artifact.figure).axes[0].get_title() and calls == [True]
    pyplot.close(artifact.figure)


def test_general_layer_trail_plot_has_layer_axis_and_exact_total():
    artifact = CircleTrail((1, 2, 3), (Fraction(-1, 2), Fraction(1, 4))).plot(show=False)
    assert dict(artifact.series)["cumulative_weight"] == (0, 1, 3)
    assert cast(Any, artifact.figure).axes[0].get_xlabel().startswith("Layer")
    pyplot.close(artifact.figure)


def test_incomplete_endpoint_result_does_not_claim_probabilities():
    with pytest.raises(ValueError, match="complete endpoint"):
        CircleApproximation(1, 1, Fraction(1, 2), complete=False).plot(show=False)
