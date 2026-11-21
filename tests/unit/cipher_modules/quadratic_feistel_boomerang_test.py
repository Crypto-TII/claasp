"""Compare rank probabilities with all actual inputs and independent round keys."""

import random
from collections import Counter
from fractions import Fraction
from itertools import combinations, product

import pytest

from claasp.cipher_modules.quadratic_feistel_boomerang import (
    QuadraticFeistelBoomerangAnalyzer,
)


def _trace(point, keys, function, inverse=False, width=2):
    left, right = point >> width, point & ((1 << width) - 1)
    states = [point]
    for key in reversed(keys) if inverse else keys:
        if inverse:
            left, right = right, left ^ function(right) ^ key
        else:
            left, right = right ^ function(left) ^ key, left
        states.append((left << width) | right)
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


def _count_all_retained_events(function, key_triples):
    counts = Counter()
    for keys in key_triples:
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
    return counts


@pytest.mark.parametrize("table", [[0, 0, 0, 1], [3, 2, 1, 3]])
def test_all_two_bit_retained_windows_match_exact_cipher_counts(table):
    function = table.__getitem__
    analyzer = QuadraticFeistelBoomerangAnalyzer(2, function)
    counts = _count_all_retained_events(function, product(range(4), repeat=3))
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


@pytest.mark.parametrize("table", [[0, 0, 0, 1], [0, 0, 0, 3]])
def test_all_fixed_key_two_bit_windows_match_actual_cipher_counts(table):
    function = table.__getitem__
    analyzer = QuadraticFeistelBoomerangAnalyzer(2, function)
    counts = [
        _count_all_retained_events(function, [(key ^ 1, key, key ^ 2)])
        for key in range(4)
    ]
    for boundary in product(range(4), repeat=6):
        probabilities = []
        for key in range(4):
            result = analyzer.analyze_fixed_key(*boundary, middle_round_key=key)
            assert result["probability"] == Fraction(counts[key][boundary], 16)
            assert result["compatible"] == bool(counts[key][boundary])
            assert result["key_model"] == "fixed_middle_key"
            assert "witness" not in result
            probabilities.append(result["probability"])
        assert sum(probabilities) / 4 == analyzer.analyze(*boundary)["probability"]


def test_fixed_key_overlap_and_disjoint_row_spaces():
    nonlinear = QuadraticFeistelBoomerangAnalyzer(
        2, lambda x: 3 * ((x & 1) * ((x >> 1) & 1))
    )
    probabilities = [
        nonlinear.analyze_fixed_key(1, 0, 0, 1, 0, 0, key)["probability"]
        for key in range(4)
    ]
    assert probabilities == [
        Fraction(3, 8),
        Fraction(3, 8),
        Fraction(1, 8),
        Fraction(1, 8),
    ]
    with pytest.raises(ValueError, match="overlap"):
        nonlinear.analyze_fixed_key(1, 0, 0, 1, 0, 0, 0, max_overlap=0)
    separated = QuadraticFeistelBoomerangAnalyzer(
        4,
        lambda x: ((x & 1) * ((x >> 1) & 1)) ^ ((((x >> 2) & 1) * ((x >> 3) & 1)) << 2),
    )
    for key in range(16):
        result = separated.analyze_fixed_key(1, 0, 0, 4, 0, 0, key, max_overlap=0)
        assert result["overlap_rank"] == 0
        assert result["key_independent"]
        assert result["probability"] == Fraction(1, 4)


@pytest.mark.parametrize(
    "keyword,cap",
    [
        (-1, 12),
        (4, 12),
        (True, 12),
        (None, 12),
        (0, -1),
        (0, True),
        (0, 1.5),
        (0, None),
    ],
)
def test_invalid_fixed_key_options(keyword, cap):
    analyzer = QuadraticFeistelBoomerangAnalyzer(2, lambda x: x)
    with pytest.raises(ValueError):
        analyzer.analyze_fixed_key(0, 0, 0, 0, 0, 0, keyword, max_overlap=cap)


@pytest.mark.parametrize("width", range(7))
def test_quadratic_character_sums_against_complete_truth_tables(width):
    from claasp.cipher_modules.quadratic_feistel_fixed_key import (
        _quadratic_character_sum,
    )

    pairs = list(combinations(range(width), 2))
    count = 1 + width + len(pairs)
    rng = random.Random(20261231 + width)
    selections = (
        range(1 << count)
        if width <= 4
        else [rng.getrandbits(count) for _ in range(512)]
    )
    for code in selections:
        constant = code & 1
        linear = code >> 1 & ((1 << width) - 1)
        edges = code >> (width + 1)
        adjacency = [0] * width
        active = []
        for bit, (i, j) in enumerate(pairs):
            if edges >> bit & 1:
                adjacency[i] |= 1 << j
                adjacency[j] |= 1 << i
                active.append((i, j))
        expected = sum(
            (-1)
            ** (
                constant
                ^ ((linear & x).bit_count() & 1)
                ^ (sum((x >> i & 1) & (x >> j & 1) for i, j in active) & 1)
            )
            for x in range(1 << width)
        )
        assert _quadratic_character_sum(constant, linear, adjacency) == expected


def _fixed_event_count(boundary, keys, function, width, nondegenerate=False):
    domain = 1 << (2 * width)
    forward = [_trace(x, keys, function, width=width) for x in range(domain)]
    backward = [_trace(x, keys, function, True, width=width) for x in range(domain)]
    alpha, beta, gamma, c, d, e = boundary
    delta, nabla = (alpha << width) | beta, (e << width) | c
    upper, lower = (gamma << width) | alpha, (c << width) | d
    count = 0
    for point, first in enumerate(forward):
        second = forward[point ^ delta]
        third, fourth = backward[first[3] ^ nabla], backward[second[3] ^ nabla]
        success = (
            third[0] ^ fourth[0] == delta
            and first[1] ^ second[1] == third[1] ^ fourth[1] == upper
            and first[2] ^ third[2] == second[2] ^ fourth[2] == lower
        )
        if nondegenerate:
            success = success and len({point, point ^ delta, third[0], fourth[0]}) == 4
        count += success
    return count


@pytest.mark.parametrize("offsets", [(1, 0, 2), (0, 5, 1)])
@pytest.mark.parametrize("keyword", [0, 0xA7])
def test_eight_bit_word_fixed_windows_match_full_state_counts(offsets, keyword):
    def rotate(value, count):
        count %= 8
        return ((value << count) | (value >> ((8 - count) % 8))) & 255

    def function(value):
        a, b, c = offsets
        return (rotate(value, a) & rotate(value, b)) ^ rotate(value, c)

    alpha = 1
    derivative = function(alpha) ^ function(0)
    boundary = (alpha, derivative, 0, alpha, 0, derivative)
    analyzer = QuadraticFeistelBoomerangAnalyzer(8, function)
    result = analyzer.analyze_fixed_key(*boundary, middle_round_key=keyword)
    actual = _fixed_event_count(boundary, [0x35, keyword, 0xC9], function, 8)
    assert result["probability"] == Fraction(actual, 1 << 16)


@pytest.mark.parametrize(
    "keyword,probability", [(0, Fraction(3, 8)), (4, Fraction(1, 8))]
)
def test_fixed_key_quadratic_variation_with_only_nondegenerate_quartets(
    keyword, probability
):
    def function(value):
        a, b, c, d, e = [(value >> i) & 1 for i in range(5)]
        return (a * c) ^ ((b * c) << 1) ^ ((d * e) << 2)

    boundary = (1, 0, 0, 2, 0, 0)
    analyzer = QuadraticFeistelBoomerangAnalyzer(5, function)
    result = analyzer.analyze_fixed_key(*boundary, middle_round_key=keyword)
    assert result["fiber_counts"] == [24, 8]
    assert not result["key_independent"]
    assert result["probability"] == probability
    count = _fixed_event_count(boundary, [3, keyword, 7], function, 5)
    nondegenerate = _fixed_event_count(
        boundary, [3, keyword, 7], function, 5, nondegenerate=True
    )
    assert count == nondegenerate == 1024 * probability


def test_simon48_saved_window_is_key_independent_when_derivative_rows_are_disjoint():
    def rotate(value, count):
        return ((value << count) | (value >> (24 - count))) & 0xFFFFFF

    def function(value):
        return (rotate(value, 1) & rotate(value, 8)) ^ rotate(value, 2)

    analyzer = QuadraticFeistelBoomerangAnalyzer(24, function)
    for keyword in (0, 0x123456, 0xFFFFFF):
        result = analyzer.analyze_fixed_key(
            0x80, 0x22, 0x222, 8, 0x200022, 0x200002, keyword
        )
        assert result["overlap_rank"] == 0
        assert result["key_independent"]
        assert result["stacked_rank"] == 4
        assert result["uniform_middle_key_rank"] == 5
        assert result["probability"] == Fraction(1, 32)
