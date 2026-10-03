from itertools import combinations, product

import pytest

from claasp.domains import BinaryExtensionField
from claasp.primitives.toy_primitives import (
    CipherFour,
    Fancy,
    Heys,
    ToyAES,
    ToyFeistel,
    ToySPN1,
    ToySPN2,
)
from claasp.primitives.toy_primitives.toyaes import MIX_COLUMN_MATRICES
from claasp.utils import binary_field_multiply


def test_fixed_toy_fixture_vectors():
    assert CipherFour().evaluate(0x1234, 0x111122223333444455556666) == 0x45E9
    assert (
        CipherFour(block_bit_size=16, key_bit_size=80, number_of_rounds=10).evaluate(
            0x5678, 0x22224444666688889999AAAA
        )
        == 0xBEEC
    )
    assert Heys().evaluate(0x1234, 0x0123456789ABCDEF0123) == 0xE582
    assert Fancy(number_of_rounds=1).evaluate(0, 0xFFFFFF) == 0xFEDCBA
    assert Fancy().evaluate(0, 0xFFFFFF) == 0xCA3417
    assert ToyFeistel().evaluate(0x3F, 0x3F) == 0x8E
    assert ToySPN1().evaluate(0x3F, 0x3F) == 0x3F
    assert ToySPN2().evaluate(0x3F, 0x01) == 0x1D


def test_fancy_is_not_a_block_permutation_after_its_lossy_odd_round():
    primitive = Fancy(number_of_rounds=2)
    assert primitive.evaluate(0x684, 0xFFFFFF) == 0x20DEFC
    assert primitive.evaluate(0x120A, 0xFFFFFF) == 0x20DEFC


def test_toy_aes_catalogue_default_does_not_classify_lossy_custom_word_sizes():
    custom = ToyAES(word_size=2, state_size=2)
    assert custom.evaluate(0, 1) == 0x2A
    assert custom.evaluate(0, 2) == 0x2A


@pytest.mark.parametrize(
    "word_size,state_size,key,plaintext,ciphertext",
    (
        (
            8,
            4,
            0x2B7E151628AED2A6ABF7158809CF4F3C,
            0x6BC1BEE22E409F96E93D7E117393172A,
            0x3AD77BB40D7A3660A89ECAF32466EF97,
        ),
        (8, 3, 0x2B7E151628AED2A6AB, 0x6BC1BEE22E409F96E9, 0xF8666F8D0BA0DCFCED),
        (8, 2, 0x2B7E1516, 0x6BC1BEE2, 0xDBBDD038),
        (4, 4, 0x2B7E151628AED2A6, 0x6BC1BEE22E409F96, 0x0E51FF61DAC37A78),
        (
            4,
            3,
            0b100111100101111110011110010111110000,
            0b100111100101111110011110010111110000,
            0x3A54A9D02,
        ),
        (4, 2, 0x2B7E, 0x6BC1, 0xA1FE),
        (3, 4, 0x2B7E151628AE, 0x6BC1BEE22E40, 0x33D9C96FE11C),
        (3, 3, 0b101101101101101101100011011, 0b100001111011110101101100010, 0x0595C25B),
        (3, 2, 0x2B7, 0x6BC, 0x2C8),
        (2, 4, 0x2B7E1516, 0x6BC1BEE2, 0x41BED50E),
        (2, 3, 0b101101101100011011, 0b011110101101100010, 0x00DE3C),
        (2, 2, 0x2B, 0x6B, 0x1F),
    ),
)
def test_toy_aes_fixed_parameter_family(word_size, state_size, key, plaintext, ciphertext):
    assert ToyAES(word_size=word_size, state_size=state_size).evaluate(key, plaintext) == ciphertext


def _rank(matrix, field):
    rows = [list(row) for row in matrix]
    rank = 0
    for column in range(len(rows[0])):
        pivot = next((row for row in range(rank, len(rows)) if rows[row][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = next(
            value
            for value in range(1, 1 << field.degree)
            if binary_field_multiply(field, rows[rank][column], value) == 1
        )
        rows[rank] = [binary_field_multiply(field, value, inverse) for value in rows[rank]]
        for row in range(len(rows)):
            if row != rank and rows[row][column]:
                factor = rows[row][column]
                rows[row] = [
                    left ^ binary_field_multiply(field, factor, right)
                    for left, right in zip(rows[row], rows[rank])
                ]
        rank += 1
    return rank


def _is_mds(matrix, field):
    size = len(matrix)
    for order in range(1, size + 1):
        for row_indices in combinations(range(size), order):
            for column_indices in combinations(range(size), order):
                minor = tuple(
                    tuple(matrix[row][column] for column in column_indices) for row in row_indices
                )
                if _rank(minor, field) != order:
                    return False
    return True


@pytest.mark.parametrize("word_size,state_size", sorted(MIX_COLUMN_MATRICES))
def test_toy_aes_matrix_mds_status_is_independently_checked(word_size, state_size):
    primitive = ToyAES(number_of_rounds=1, word_size=word_size, state_size=state_size)
    field = BinaryExtensionField(word_size, primitive.irreducible_polynomial)
    expected = (word_size, state_size) != (2, 4)
    assert _is_mds(MIX_COLUMN_MATRICES[(word_size, state_size)], field) is expected
    if not expected:
        matrix = MIX_COLUMN_MATRICES[(word_size, state_size)]
        weights = []
        for vector in product(range(1 << word_size), repeat=state_size):
            if any(vector):
                output = [0] * state_size
                for row in range(state_size):
                    for coefficient, value in zip(matrix[row], vector):
                        output[row] ^= binary_field_multiply(field, coefficient, value)
                weights.append(sum(value != 0 for value in vector + tuple(output)))
        assert min(weights) == 3


def test_reduced_and_custom_toy_parameters():
    assert ToyFeistel().evaluate(0x3F, 0x3E) == 0x20
    assert (
        ToySPN1(block_bit_size=9, key_bit_size=9, number_of_rounds=10).evaluate(0x1FF, 0x1FE)
        == 0x173
    )
    table = tuple(range(1, 16)) + (0,)
    assert ToySPN1(8, 8, -2, table, 10).evaluate(0xFF, 0xFE) == 0x6C
