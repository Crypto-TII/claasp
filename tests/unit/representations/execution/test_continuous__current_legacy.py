"""Generalized Speck evaluation, without conflating different sampling schemes."""

import json
from pathlib import Path

import pytest

from claasp.primitives import Speck

DATA = json.loads(Path("tests/fixtures/legacy_parity/diffusion.json").read_text())


@pytest.mark.parametrize("case", DATA["continuous"])
def test_fixed_correlation_inputs_match_current_legacy_decimal_evaluator(case):
    result = Speck(number_of_rounds=case["rounds"]).analysis.continuous_evaluate(
        {name: tuple(float(value) for value in values) for name, values in case["inputs"].items()},
        carry_order="legacy_msb_first",
    )
    assert result.output == pytest.approx(
        tuple(float(value) for value in case["expected"]), abs=1e-12
    )
