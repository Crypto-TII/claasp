"""Exhaustive independent AND DDT/LAT counts, including fixed legacy tables."""

from itertools import product

from claasp_next.semantics.cryptanalysis import BitwiseAndSemantics


def test_bitwise_and_ddt_lat_match_exhaustive_two_bit_words():
    semantics = BitwiseAndSemantics(2)
    for left, right, output in product(range(4), repeat=3):
        count = sum(((x & y) ^ ((x ^ left) & (y ^ right))) == output
                    for x, y in product(range(4), repeat=2))
        walsh = sum((-1) ** (((x & left).bit_count() + (y & right).bit_count()
                             + ((x & y) & output).bit_count()) % 2)
                    for x, y in product(range(4), repeat=2))
        differential = semantics.xor_differential(left, right, output)
        linear = semantics.xor_linear(left, right, output)
        assert differential.numerator == count
        assert linear.numerator * linear.sign == walsh
        assert semantics.check(differential) and semantics.check(linear)


def test_legacy_cp_and_probability_arrays_are_retained():
    semantics = BitwiseAndSemantics(1)
    assert [semantics.xor_differential(left, right, output).numerator
            for left, right, output in product(range(2), repeat=3)] == [4, 0, 2, 2, 2, 2, 2, 2]
    assert [semantics.xor_linear(left, right, output).numerator
            * semantics.xor_linear(left, right, output).sign // 2
            for left, right, output in product(range(2), repeat=3)] == [2, 1, 0, 1, 0, 1, 0, -1]
