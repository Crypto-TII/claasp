"""Circle-linear reports preserve evidence scope and never rerun an analysis."""

import os
import subprocess
import sys
from fractions import Fraction
from io import StringIO

import pytest

from claasp.analysis.circle_linear import CircleApproximation, CircleCorrelationEstimate
from claasp.presentation._circle_linear import trail_profile
from claasp.primitives import Craft
from claasp.semantics.cryptanalysis.circle_linear import CircleTrail


def test_endpoint_terminal_reports_exactness_and_signed_correlation():
    output = StringIO()
    CircleApproximation(7, 14, Fraction(-1)).to_terminal(file=output)
    text = output.getvalue()
    assert "endpoint approximation" in text
    assert "0x7" in text and "0xe" in text and "-1" in text
    estimate = CircleCorrelationEstimate(0.25, 100, 17, 0.09, -0.1, 0.6, 0.95)
    output = StringIO()
    estimate.to_terminal(file=output)
    assert "Empirical" in output.getvalue()
    assert "[-0.1, 0.6]" in output.getvalue()
    assert "17" in output.getvalue()


def test_search_and_selected_trail_report_distinguish_scope_without_research(monkeypatch):
    model = Craft(number_of_rounds=8).circle_linear_trail_model()
    result = model.search()
    monkeypatch.setattr(type(model), "search", lambda *a, **k: pytest.fail("search repeated"))
    for value in (result, result.representative):
        output = StringIO()
        value.to_terminal(details=True, file=output)
        text = output.getvalue()
        assert "trail contribution" in text
        assert "not an endpoint-correlation lower bound" in text
        assert "2^120" in text and "Cumulative weight (bits)" in text
    output = StringIO()
    result.to_terminal(file=output)
    text = output.getvalue()
    assert result.scope in text and "Round trail" in text
    assert "Relative |correlation|" in text and "Cumulative |trail contribution|" in text
    assert "Optimal masks" not in text  # Search metadata belongs to details=True.
    output = StringIO()
    result.representative.to_terminal(file=output)
    assert "no optimality claim" in output.getvalue()


def test_layer_trail_keeps_negative_sign_and_zero_weight_plot_refusal():
    trail = CircleTrail((1, 2, 3), (Fraction(-1, 2), Fraction(1, 4)))
    output = StringIO()
    trail.to_terminal(details=True, file=output)
    assert "-1/8" in output.getvalue()
    assert trail_profile(trail) == ("Layer", (0.0, 1.0, 2.0), (0.0, 1.0, 3.0))
    with pytest.raises(ValueError, match="nonzero"):
        trail_profile(CircleTrail((0, 1), (Fraction(0),)))


def test_terminal_is_dependency_free_in_a_fresh_process():
    program = """
import sys
from fractions import Fraction
from claasp.analysis.circle_linear import CircleApproximation
CircleApproximation(1, 1, Fraction(1, 2)).to_terminal()
assert 'matplotlib' not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        env=dict(os.environ, PYTHONPATH="src"),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Signed correlation" in completed.stdout
