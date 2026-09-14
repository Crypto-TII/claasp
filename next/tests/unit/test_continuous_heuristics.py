"""Preserved continuous-model fixtures, explicitly treated as heuristics."""

from math import isclose

import pytest

from claasp_next.semantics.cryptanalysis import (
    ContinuousHeuristicResult, continuous_modular_add, continuous_rotate_left,
    continuous_rotate_right, continuous_speck32, continuous_xor,
)


LEFT = (-1.0, -1.0, -1.0, 1.0) + (-1.0,) * 12
RIGHT = (-1.0, 1.0, -1.0, 1.0) + (-1.0,) * 12
ROUND_ONE_LEFT = (
    0.0, 0.5, 0.0, 0.984375, -0.96875, -0.9375, -0.875, -0.75,
    -0.5, 0.0, 1.0, -1.0, -1.0, -1.0, -1.0, -1.0,
)
ROUND_ONE_RIGHT = (
    0.0, -0.5, 0.0, 0.984375, -0.96875, -0.9375, -0.875, -0.75,
    -0.5, 0.0, 1.0, -1.0, -1.0, -1.0, -1.0, 1.0,
)


def test_continuous_component_vectors_preserve_legacy_scip_results():
    rotated_left = continuous_rotate_right(LEFT, 7)
    rotated_right = continuous_rotate_left(RIGHT, 2)
    added = continuous_modular_add(rotated_left, RIGHT)

    assert rotated_left[10] == 1
    assert rotated_right[1] == 1 and rotated_right[15] == 1
    assert all(isclose(value, expected, abs_tol=1e-9) for value, expected in zip(added, ROUND_ONE_LEFT))
    assert continuous_xor(added, rotated_right) == ROUND_ONE_RIGHT


def test_continuous_speck_preserves_one_and_two_round_legacy_vectors():
    one = continuous_speck32(LEFT, RIGHT, rounds=1)
    two = continuous_speck32(LEFT, RIGHT, rounds=2)
    expected_two = (
        0.0, 0.125904, 0.0, 0.849684, -0.730319, -0.521594, -0.163504, 0.0,
        -0.003400, 0.0, -0.877274, -0.785400, -0.631694, -0.382812, 0.0, 0.5,
        0.0, -0.123896, 0.0, 0.796585, -0.639005, -0.391206, -0.081797, 0.0,
        0.003400, 0.0, -0.877274, -0.785400, -0.631695, 0.382810, 0.0, 0.25,
    )

    assert one.values == ROUND_ONE_LEFT + ROUND_ONE_RIGHT
    assert all(isclose(value, expected, abs_tol=1e-4) for value, expected in zip(two.values, expected_two))
    assert two.claim_kind == "heuristic"
    assert not hasattr(two, "is_satisfiable") and not hasattr(two, "is_optimal")


def test_fixed_mask_correlation_retains_tolerance_and_numeric_provenance():
    result = continuous_speck32(LEFT, RIGHT, rounds=2)
    mask = tuple(int(index in (3, 26)) for index in range(32))

    assert isclose(result.selected_correlation(mask), 0.7454814092873888, abs_tol=1e-6)
    assert isclose(result.selected_weight(mask), 0.4237557196600851, abs_tol=1e-6)
    assert result.precision == "binary64" and result.tolerance == 1e-4


def test_continuous_result_rejects_exact_status_and_invalid_range():
    with pytest.raises(ValueError, match="proof status"):
        ContinuousHeuristicResult((0.0,), 1e-4, "test", claim_kind="optimal")
    with pytest.raises(ValueError, match=r"\[-1, 1\]"):
        ContinuousHeuristicResult((1.1,), 1e-4, "test")
