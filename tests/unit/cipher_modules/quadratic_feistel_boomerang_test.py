"""Compare rank probabilities with all actual inputs and independent round keys."""

from collections import Counter
from fractions import Fraction
from itertools import product

import pytest

from claasp.cipher_modules.quadratic_feistel_boomerang import (
    QuadraticFeistelBoomerangAnalyzer,
)


def _trace(point, keys, function, inverse=False):
    left, right = point >> 2, point & 3
    states = [point]
    for key in reversed(keys) if inverse else keys:
        if inverse:
            left, right = right, left ^ function(right) ^ key
        else:
            left, right = right ^ function(left) ^ key, left
        states.append((left << 2) | right)
    return list(reversed(states)) if inverse else states


def _check_witness(boundary, witness, function):
    alpha, beta, gamma, c, d, e = boundary
    first = _trace(witness["input"], witness["keys"], function)
    second = _trace(witness["input"] ^ (alpha << 2 | beta), witness["keys"], function)
    third = _trace(first[3] ^ (e << 2 | c), witness["keys"], function, True)
    fourth = _trace(second[3] ^ (e << 2 | c), witness["keys"], function, True)
    assert first[1] ^ second[1] == third[1] ^ fourth[1] == (gamma << 2 | alpha)
    assert first[2] ^ third[2] == second[2] ^ fourth[2] == (c << 2 | d)
    assert third[0] ^ fourth[0] == (alpha << 2 | beta)


def _verify_certificate(system):
    mask = rhs = 0
    for i, (row, value) in enumerate(system["rows"]):
        if system["contradiction"] >> i & 1:
            mask ^= row
            rhs ^= value
    assert (mask, rhs) == (0, 1)


@pytest.mark.parametrize("table", [[0, 0, 0, 1], [3, 2, 1, 3]])
def test_all_two_bit_retained_windows_match_exact_cipher_counts(table):
    function = table.__getitem__
    analyzer = QuadraticFeistelBoomerangAnalyzer(2, function)
    counts = Counter()
    for keys in product(range(4), repeat=3):
        forward = [_trace(x, keys, function) for x in range(16)]
        inverse = [_trace(x, keys, function, True) for x in range(16)]
        for point, first in enumerate(forward):
            for delta in range(16):
                second = forward[point ^ delta]
                middle = first[1] ^ second[1]
                for nabla in range(16):
                    third, fourth = (
                        inverse[first[3] ^ nabla],
                        inverse[second[3] ^ nabla],
                    )
                    if third[0] ^ fourth[0] != delta or third[1] ^ fourth[1] != middle:
                        continue
                    lower = first[2] ^ third[2]
                    if second[2] ^ fourth[2] == lower:
                        counts[
                            (
                                delta >> 2,
                                delta & 3,
                                middle >> 2,
                                lower >> 2,
                                lower & 3,
                                nabla >> 2,
                            )
                        ] += 1
    for boundary in product(range(4), repeat=6):
        result = analyzer.analyze(*boundary)
        assert isinstance(result["probability"], Fraction)
        assert result["probability"] == Fraction(counts[boundary], 1024)
        assert result["compatible"] == bool(counts[boundary])
        if result["compatible"]:
            _check_witness(boundary, result["witness"], function)
        else:
            for system in result.get("systems", {}).values():
                if not system["consistent"]:
                    _verify_certificate(system)


@pytest.mark.parametrize("width", [0, -1, True, 1.5, "2"])
def test_invalid_word_size(width):
    with pytest.raises(ValueError, match="positive integer"):
        QuadraticFeistelBoomerangAnalyzer(width, lambda x: x)


@pytest.mark.parametrize("function", [None, lambda x: -1, lambda x: 4, lambda x: 0.5])
def test_invalid_round_function(function):
    with pytest.raises(ValueError):
        QuadraticFeistelBoomerangAnalyzer(2, function)


@pytest.mark.parametrize("value", [-1, 4, 0.5, "1"])
def test_invalid_boundary_word(value):
    analyzer = QuadraticFeistelBoomerangAnalyzer(2, lambda x: x)
    with pytest.raises(ValueError, match="Differences"):
        analyzer.analyze(value, 0, 0, 0, 0, 0)


def test_round_function_output_is_checked_beyond_zero():
    analyzer = QuadraticFeistelBoomerangAnalyzer(2, lambda x: 4 if x else 0)
    with pytest.raises(ValueError, match="does not fit"):
        analyzer.analyze(1, 0, 0, 0, 0, 0)


def test_joint_obstruction_despite_individually_feasible_arms():
    analyzer = QuadraticFeistelBoomerangAnalyzer(2, lambda x: (x & 1) * ((x >> 1) & 1))
    result = analyzer.analyze(1, 0, 0, 2, 0, 0)
    assert not result["compatible"] and result["probability"] == 0
    assert result["systems"]["upper"]["consistent"]
    assert result["systems"]["lower"]["consistent"]
    _verify_certificate(result["systems"]["joint"])
