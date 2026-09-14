"""Preserved fixed algebraic evidence from legacy CLAASP."""

from dataclasses import replace

import pytest

from claasp_next.analysis import analyze_boolean_algebra
from claasp_next.ciphers import SimonBlockCipher


@pytest.fixture(scope="module")
def simon_four_round_evidence():
    noncube_plaintext = {f"p{index}": 0 for index in range(32) if index not in (1, 2)}
    return analyze_boolean_algebra(
        SimonBlockCipher(number_of_rounds=4),
        cube=("p1", "p2"),
        fixed_variables=noncube_plaintext,
    )


def test_exact_simon_degrees_preserve_legacy_fixture(simon_four_round_evidence):
    assert simon_four_round_evidence.output_degrees == (8,) * 16 + (5,) * 16


def test_exact_simon_superpoly_parity_preserves_legacy_fixture(simon_four_round_evidence):
    assert simon_four_round_evidence.cube_degrees == (
        -1, -1, -1, -1, 2, 3, -1, -1, 3, -1, -1, -1, -1, 3, 3, 3,
        1, -1, -1, -1, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    )
    assert 0 in simon_four_round_evidence.balanced_output_bits
    assert 4 not in simon_four_round_evidence.balanced_output_bits
    assert simon_four_round_evidence.complete


def test_incomplete_evidence_cannot_be_used_as_a_proof(simon_four_round_evidence):
    with pytest.raises(RuntimeError, match="incomplete"):
        replace(simon_four_round_evidence, complete=False).require_complete()


def test_fixed_variables_require_a_cube():
    with pytest.raises(ValueError, match="require a cube"):
        analyze_boolean_algebra(
            SimonBlockCipher(number_of_rounds=1), fixed_variables={"p0": 0}
        )
