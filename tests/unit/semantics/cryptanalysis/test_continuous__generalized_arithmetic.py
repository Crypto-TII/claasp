"""Boolean vertices and independent truth-table checks for continuous ARX."""

from itertools import product

import pytest

from claasp.semantics.cryptanalysis import (
    continuous_modular_add,
    continuous_modular_subtract,
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


@pytest.mark.parametrize(
    "plaintext,key", [(0, 0), (0x12345678, 0x0102030405060708), (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)]
)
def test_generalized_speck_agrees_with_concrete_evaluation_at_boolean_vertices(plaintext, key):
    from claasp.primitives import Speck

    primitive = Speck(number_of_rounds=3)
    result = primitive.analysis.continuous_evaluate(
        {"plaintext": _bits(plaintext, 32), "key": _bits(key, 64)}
    )
    assert result.output == _bits(primitive.evaluate(plaintext, key), 32)
