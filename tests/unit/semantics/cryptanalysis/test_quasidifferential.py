"""Signed carry-DP oracle checked against exhaustive paired evaluations."""

from fractions import Fraction
from itertools import product
from random import Random

import pytest

from claasp.semantics.cryptanalysis.quasidifferential import QuasidifferentialSemantics as Q


@pytest.mark.parametrize("width", [1, 2])
def test_modular_addition_all_differences_and_masks(width):
    modulus = 1 << width
    table = tuple(
        ((x >> width) + (x & (modulus - 1))) & (modulus - 1) for x in range(modulus * modulus)
    )
    for a, b, c, u, v, w in product(range(modulus), repeat=6):
        assert Q.modular_add(width, a, b, c, u, v, w) == Q.lookup(
            table, (a << width) | b, c, (u << width) | v, w, output_width=width
        )


def test_subtraction_role_permutation_and_three_bit_samples():
    rng = Random(9)
    width = 3
    table = tuple(((x >> width) - (x & 7)) & 7 for x in range(64))
    for _ in range(256):
        a, b, c, u, v, w = (rng.randrange(8) for _ in range(6))
        assert Q.modular_subtract(width, a, b, c, u, v, w) == Q.lookup(
            table, (a << width) | b, c, (u << width) | v, w, output_width=width
        )


def test_large_word_coefficients_are_exact_and_do_not_enumerate_inputs():
    assert Q.modular_add(64, 0, 0, 0, 0, 0, 0) == 1
    assert Q.modular_add(64, 1, 0, 1, 0, 0, 0) == Fraction(1, 2)
    assert Q.modular_add(64, 0, 0, 1, 0, 0, 0) == 0


def test_nonbijective_table_and_negative_coefficient():
    assert Q.lookup((0, 0, 0, 1), 0, 0, 1, 1, output_width=1) == Fraction(1, 2)
    assert Q.lookup((1, 0), 0, 0, 1, 1) == -1
    with pytest.raises(ValueError):
        Q.lookup((0, 1), 2, 0, 0, 0)
