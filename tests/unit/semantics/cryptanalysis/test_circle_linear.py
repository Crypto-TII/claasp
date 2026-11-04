"""Exact quadratic kernels checked against independent exhaustive evaluation."""

from fractions import Fraction
from itertools import product
from random import Random

import pytest

from claasp.semantics.cryptanalysis._circle_algebra import evaluate, gauss_sum, radical
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.semantics.cryptanalysis.circle_linear import (
    AffineKeyConditions,
    CircleAffineLayer,
    CircleLookupLayer,
    CircleNetwork,
    CircleTrail,
)


def test_random_quadratic_gauss_sums_include_sign_and_linear_radical():
    rng = Random(77)
    for width in range(1, 8):
        monomials = (
            [0]
            + [1 << i for i in range(width)]
            + [(1 << i) | (1 << j) for i in range(width) for j in range(i + 1, width)]
        )
        for _ in range(30):
            poly = frozenset(term for term in monomials if rng.getrandbits(1))
            direct = Fraction(sum((-1) ** evaluate(poly, x) for x in range(1 << width)), 1 << width)
            assert gauss_sum(poly) == direct
            for r in radical(poly, width):
                assert all(
                    evaluate(poly, x ^ r) ^ evaluate(poly, x)
                    == evaluate(poly, r) ^ evaluate(poly, 0)
                    for x in range(1 << width)
                )


def test_affine_grouped_layers_match_full_truth_tables_and_exact_key_classes():
    rng = Random(90)
    brace = BinaryBibrace.craft()
    basis = CircleBasis((brace,))
    for _ in range(4):
        rows = tuple(rng.randrange(16) for _ in range(4))
        key_rows = tuple(rng.randrange(4) for _ in range(4))
        offset = rng.randrange(16)
        layer = CircleAffineLayer(basis, basis, rows, offset, 2, key_rows)
        for a, b in product(range(16), repeat=2):
            t = layer.transition(a, b)
            survivors = 0
            for key in range(4):
                total = 0
                for x in range(16):
                    y = offset ^ sum(
                        (((rows[i] & x).bit_count() ^ (key_rows[i] & key).bit_count()) & 1) << i
                        for i in range(4)
                    )
                    total += (-1) ** (brace.character(a, x) ^ brace.character(b, y))
                coefficient = Fraction(total, 16)
                assert t.coefficient(key) == coefficient
                assert t.conditions.contains(key) == bool(coefficient)
                if coefficient:
                    assert abs(coefficient) == t.magnitude
                    survivors += 1
            assert t.conditions.key_count == survivors


def test_rectangular_noninvertible_affine_layer_and_mixed_layout():
    a = CircleBasis((BinaryBibrace(3),))
    b = CircleBasis((BinaryBibrace(1), BinaryBibrace(1)))
    layer = CircleAffineLayer(a, b, (1, 1), offset=2)
    for u, v in product(range(8), range(4)):
        expected = Fraction(
            sum((-1) ** (a.character(u, x) ^ b.character(v, ((x & 1) * 3) ^ 2)) for x in range(8)),
            8,
        )
        assert layer.coefficient(u, v) == expected


def test_affine_pullback_does_not_treat_repeated_subkeys_as_independent():
    conditions = AffineKeyConditions(3, ((1, 0), (2, 1)))
    assert conditions.key_count == 2
    assert conditions.pullback((1, 1, 2), 2).key_count == 0
    assert conditions.pullback((1, 1, 2), 2, offset=2).key_count == 2
    with pytest.raises(ValueError):
        conditions.intersect(AffineKeyConditions(2))


def test_existential_projection_matches_exhaustive_key_set():
    rng = Random(8)
    for _ in range(30):
        conditions = AffineKeyConditions(
            5, tuple((rng.randrange(32), rng.randrange(2)) for _ in range(4))
        )
        positions = (3, 0, 4)
        projected = conditions.project(positions)
        expected = {
            sum(((key >> old) & 1) << new for new, old in enumerate(positions))
            for key in range(32)
            if conditions.contains(key)
        }
        assert {key for key in range(8) if projected.contains(key)} == expected
        assert projected.key_count == len(expected)


def test_hull_cancellation_can_annihilate_nonzero_best_trail():
    # Two identical nonlinear involutions compose to identity. Pick endpoints
    # with zero identity correlation but nonzero trails through the middle.
    table = (0, 1, 2, 3, 4, 5, 7, 6)
    basis = CircleBasis((BinaryBibrace(3),))
    layer = CircleLookupLayer(basis, basis, table)
    network = CircleNetwork((layer, layer))
    trail = network.best_trail(1, 3)
    assert trail is not None and trail.coefficient != 0
    assert network.correlation(1, 3) == 0
    assert sum((network.trail((1, middle, 3)).coefficient for middle in range(8)), Fraction(0)) == 0


def test_network_dynamic_program_matches_exhaustive_all_trails_and_composition():
    basis = CircleBasis((BinaryBibrace(2),))
    first = CircleLookupLayer(basis, basis, (0, 1, 3, 2))
    second = CircleLookupLayer(basis, basis, (3, 1, 0, 2))
    network = CircleNetwork((first, second))
    for a, b in product(range(4), repeat=2):
        trails = [network.trail((a, middle, b)) for middle in range(4)]
        expected = Fraction(
            sum(
                (-1) ** (basis.character(a, x) ^ basis.character(b, second.table[first.table[x]]))
                for x in range(4)
            ),
            4,
        )
        assert network.correlation(a, b) == expected
        best = network.best_trail(a, b)
        assert (abs(best.coefficient) if best else 0) == max(abs(t.coefficient) for t in trails)
    with pytest.raises(ValueError, match="maximum_entries"):
        network.correlation(1, 1, maximum_entries=1)


def test_network_key_phases_are_not_dropped():
    b = CircleBasis((BinaryBibrace(1),))
    network = CircleNetwork(
        (CircleAffineLayer(b, b, (1,), key_width=1, key_rows=(1,)), CircleLookupLayer(b, b, (0, 1)))
    )
    assert network.correlation(1, 1, key=1) == -1
    best = network.best_trail(1, 1, key=1)
    assert best is not None and best.coefficient == -1


@pytest.mark.parametrize(
    "make",
    [
        lambda: CircleTrail((0,), ()),
        lambda: CircleTrail((0, 0), (Fraction(2),)),
        lambda: AffineKeyConditions(2, ((4, 0),)),
        lambda: AffineKeyConditions(2, ((1, 2),)),
        lambda: CircleNetwork(()),
        lambda: CircleLookupLayer(
            CircleBasis((BinaryBibrace(3),)), CircleBasis((BinaryBibrace(3),)), tuple(range(8)), 7
        ),
    ],
)
def test_invalid_contracts_and_budgets(make):
    with pytest.raises(ValueError):
        make()
