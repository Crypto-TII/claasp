"""Same samples and bit order, executed independently in pinned legacy CLAASP."""

import json
from pathlib import Path

from claasp.primitives import Speck

DATA = json.loads(Path("tests/fixtures/legacy_parity/diffusion.json").read_text())


def test_numpy_round_probability_matrices_match_current_legacy_counts():
    expected = DATA["avalanche"]
    result = Speck(number_of_rounds=expected["rounds"]).analysis.avalanche(
        "plaintext",
        expected["samples"],
        seed=expected["seed"],
    )
    assert result.method == "numpy_paired_evaluation"
    assert result.round_numbers == (1, 2, 3)
    assert result.round_probabilities == tuple(
        tuple(tuple(count / expected["samples"] for count in row) for row in matrix)
        for matrix in expected["counts"]
    )
