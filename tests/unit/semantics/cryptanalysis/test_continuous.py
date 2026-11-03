"""Boolean vertices and independent truth-table checks for continuous ARX."""

from itertools import product

import pytest

from claasp.semantics.cryptanalysis import (
    ContinuousHeuristicResult,
    continuous_modular_add,
    continuous_modular_subtract,
    continuous_speck32,
)


def _bits(value, width):
    return tuple(float(2 * ((value >> shift) & 1) - 1) for shift in reversed(range(width)))


@pytest.mark.parametrize("width", [1, 2, 3, 4])
def test_add_and_subtract_agree_with_integer_arithmetic_at_every_boolean_vertex(width):
    for left, right in product(range(1 << width), repeat=2):
        a, b = _bits(left, width), _bits(right, width)
        assert continuous_modular_add(a, b) == _bits((left + right) % (1 << width), width)
        assert continuous_modular_subtract(a, b) == _bits((left - right) % (1 << width), width)


def test_continuous_majority_matches_independent_bernoulli_enumeration():
    a, b, c = 0.2, -0.6, 0.4
    expected = 0.0
    for x, y, z in product((0, 1), repeat=3):
        probability = 1.0
        for bit, mean in zip((x, y, z), (a, b, c)):
            probability *= (1 + (2 * bit - 1) * mean) / 2
        expected += probability * (2 * int(x + y + z >= 2) - 1)
    # The low bit generates a carry with mean c=0.4: adding Boolean 1
    # to a bit of mean c produces exactly that carry.
    output = continuous_modular_add((a, 1.0), (b, c))
    assert output[0] == pytest.approx(a * b * c)
    # Exercise a second carry stage, whose majority is now observable.
    result = continuous_modular_add((1.0, a, 1.0), (1.0, b, c))
    assert result[0] == pytest.approx(expected)


def test_specialized_speck_with_zero_round_keys_matches_integer_rounds():
    left, right = 0x1000, 0x5000
    expected_left, expected_right = left, right
    for rounds in range(1, 4):
        expected_left = (((expected_left >> 7) | (expected_left << 9)) + expected_right) & 0xFFFF
        expected_right = (((expected_right << 2) | (expected_right >> 14)) & 0xFFFF) ^ expected_left
        result = continuous_speck32(_bits(left, 16), _bits(right, 16), rounds=rounds)
        assert result.values == _bits(expected_left, 16) + _bits(expected_right, 16)
        assert result.claim_kind == "heuristic"
        assert not hasattr(result, "is_optimal")


def test_fixed_mask_correlation_retains_tolerance_and_numeric_provenance():
    result = ContinuousHeuristicResult((0.5, -0.5), 1e-4, "independent example")
    assert result.selected_correlation((1, 1)) == 0.25
    assert result.selected_weight((1, 1)) == 2
    assert result.precision == "binary64" and result.tolerance == 1e-4


def test_continuous_result_rejects_exact_status_and_invalid_range():
    with pytest.raises(ValueError, match="proof status"):
        ContinuousHeuristicResult((0.0,), 1e-4, "test", claim_kind="optimal")
    with pytest.raises(ValueError, match=r"\[-1, 1\]"):
        ContinuousHeuristicResult((1.1,), 1e-4, "test")
