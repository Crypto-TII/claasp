"""Independent group, character and Walsh oracles for binary bibraces."""

from collections import Counter
from itertools import product

import pytest

from claasp.primitives.block_ciphers.craft import CRAFT_SBOX
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis


def _parity(x):
    return x.bit_count() & 1


def test_paper_operation_characters_and_orthogonality():
    brace = BinaryBibrace.craft()
    for x, y in product(range(16), repeat=2):
        psi = (((x ^ (x >> 2)) & 1) * (y >> 3)) ^ ((x >> 3) * ((y ^ (y >> 2)) & 1))
        assert brace.circle(x, y) == x ^ y ^ (5 if psi else 0)
        assert brace.theta(x ^ y) == brace.circle(brace.theta(x), brace.theta(y))
        for u in range(16):
            expected = _parity(u & x) ^ (_parity(u & 5) * (((x ^ (x >> 2)) & 1) * (x >> 3)))
            assert brace.character(u, x) == expected
            assert brace.character(u, brace.circle(x, y)) == brace.character(
                u, x
            ) ^ brace.character(u, y)
    for x, y, z in product(range(16), repeat=3):
        assert brace.circle(brace.circle(x, y), z) == brace.circle(x, brace.circle(y, z))
    for a, b in product(range(16), repeat=2):
        assert sum((-1) ** (brace.character(a, x) ^ brace.character(b, x)) for x in range(16)) == (
            16 if a == b else 0
        )


def test_paper_table_2_against_direct_character_sum():
    brace = BinaryBibrace.craft()
    walsh = brace.walsh_table(CRAFT_SBOX)
    direct = tuple(
        tuple(
            sum(
                (-1) ** (brace.character(a, x) ^ brace.character(b, CRAFT_SBOX[x]))
                for x in range(16)
            )
            for b in range(16)
        )
        for a in range(16)
    )
    assert walsh == direct
    assert Counter(abs(walsh[a][b]) for a in range(1, 16) for b in range(1, 16)) == {
        0: 174,
        8: 48,
        16: 3,
    }
    assert [
        (a, b, walsh[a][b]) for a in range(16) for b in range(16) if abs(walsh[a][b]) == 16
    ] == [(0, 0, 16), (7, 14, -16), (9, 9, 16), (14, 7, -16)]


def test_refinement_correction_when_naive_quadratic_does_not_vanish_on_b():
    brace = BinaryBibrace(3, ((6, 5, 3),), (7,))
    for x, y in product(range(8), repeat=2):
        assert brace.theta(brace.theta(x)) == x
        assert brace.theta(x ^ y) == brace.circle(brace.theta(x), brace.theta(y))


def test_higher_rank_and_heterogeneous_parallel_layout():
    brace = BinaryBibrace(6, ((2, 1, 0, 0, 0, 0), (0, 0, 8, 4, 0, 0)), (16, 32))
    for x, y in product(range(64), repeat=2):
        assert brace.theta(x ^ y) == brace.circle(brace.theta(x), brace.theta(y))
        assert brace.theta(brace.theta(x)) == x
    basis = CircleBasis((BinaryBibrace.craft(), brace))
    for x in range(1024):
        assert basis.theta(x) == (BinaryBibrace.craft().theta(x >> 6) << 6) | brace.theta(x & 63)


def test_nonpermutation_keeps_declared_output_width():
    table = BinaryBibrace(4).walsh_table((0,) * 16)
    assert len(table) == len(table[0]) == 16
    assert table[0][15] == 16


@pytest.mark.parametrize(
    "make",
    [
        lambda: BinaryBibrace(0),
        lambda: BinaryBibrace(True),
        lambda: BinaryBibrace(2, ((1, 0),), (1,)),
        lambda: BinaryBibrace(2, ((2, 0),), (1,)),
        lambda: BinaryBibrace(2, ((2, 1),), (1,)),
        lambda: BinaryBibrace(3, ((2, 1, 0),), (0,)),
        lambda: BinaryBibrace(3, ((2, 1, 0), (2, 1, 0)), (4, 4)),
        lambda: BinaryBibrace(3, ((0, 0, 0),), (4,)),
        lambda: CircleBasis(()),
    ],
)
def test_invalid_structures_are_rejected(make):
    with pytest.raises(ValueError):
        make()


def test_bad_labels_domains_and_table_budget():
    brace = BinaryBibrace.craft()
    with pytest.raises(ValueError, match="maximum_entries"):
        brace.walsh_table(CRAFT_SBOX, maximum_entries=255)
    for bad in (-1, 16, True):
        with pytest.raises(ValueError):
            brace.character(bad, 0)
    with pytest.raises(ValueError):
        brace.walsh_table((0,))


def test_all_105_nontrivial_four_bit_rank_one_bibraces():
    pairs = [(i, j) for i in range(4) for j in range(i + 1, 4)]
    count = 0
    for code in range(1, 64):
        rows = [0] * 4
        for index, (i, j) in enumerate(pairs):
            if code >> index & 1:
                rows[i] |= 1 << j
                rows[j] |= 1 << i
        for b in range(1, 16):
            if any(_parity(row & b) for row in rows):
                continue
            brace = BinaryBibrace(4, (tuple(rows),), (b,))
            assert sorted(brace.theta(x) for x in range(16)) == list(range(16))
            count += 1
    assert count == 105
