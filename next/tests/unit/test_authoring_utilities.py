"""Independent checks for migrated authoring and fixed-width helpers."""

import pytest

from claasp_next.utils import (
    bitmask,
    bits_little_endian,
    bytes_to_int,
    coerce_exact_int,
    int_to_bytes,
    int_to_words,
    reverse_bytes_in_words,
    rotate_right,
    rotate_sequence_left,
    rotate_sequence_right,
    shift_left,
    shift_right,
    words_to_int,
)


def test_legacy_integer_evidence_and_independent_bit_formula():
    assert bitmask(4) == 0b1111
    assert bitmask(32) == 0xFFFFFFFF
    expected = tuple((0x67452301 >> index) & 1 for index in range(32))
    assert bits_little_endian(0x67452301, 32) == expected


def test_word_and_byte_conversions_round_trip_both_orders():
    value = 0x01234567
    assert int_to_words(value, 8, 32) == (0x01, 0x23, 0x45, 0x67)
    assert int_to_words(value, 8, 32, byteorder="little") == (0x67, 0x45, 0x23, 0x01)
    assert words_to_int((0x01, 0x23, 0x45, 0x67), 8) == value
    assert words_to_int((0x67, 0x45, 0x23, 0x01), 8, byteorder="little") == value
    assert bytes_to_int(int_to_bytes(value, 32)) == value
    assert rotate_right(0x81, 1, 8) == 0xC0


def test_sequence_operations_preserve_type_and_fixed_legacy_results():
    assert rotate_sequence_left([1, 2, 3, 4, 5], 2) == [3, 4, 5, 1, 2]
    assert rotate_sequence_right((1, 1, 0, 1, 0, 1, 0), 4) == (1, 0, 1, 0, 1, 1, 0)
    assert shift_left([0, 1, 2], 3) == [0, 0, 0]
    assert shift_right((0, 1, 2), 0) == (0, 1, 2)
    marker = object()
    assert shift_right([1, 2, 3], 2, fill=marker) == [marker, marker, 1]


def test_layout_reverses_bytes_in_each_word_independently():
    expected = tuple(
        [24, 25, 26, 27, 28, 29, 30, 31]
        + [16, 17, 18, 19, 20, 21, 22, 23]
        + [8, 9, 10, 11, 12, 13, 14, 15]
        + [0, 1, 2, 3, 4, 5, 6, 7]
    )
    assert reverse_bytes_in_words(range(32)) == expected
    assert reverse_bytes_in_words(range(64)) == expected + tuple(position + 32 for position in expected)


@pytest.mark.parametrize("value", [True, False, "3", None, 3.5, [], {}])
def test_exact_integer_coercion_rejects_legacy_invalid_values(value):
    with pytest.raises(ValueError, match="rounds must be an integer"):
        coerce_exact_int(value, "rounds")


def test_exact_integer_and_width_validation():
    assert coerce_exact_int(5.0, "rounds") == 5
    assert coerce_exact_int(10**100, "rounds") == 10**100
    with pytest.raises(ValueError, match="fit in 7 bits"):
        int_to_words(0x80, 1, 7)
    with pytest.raises(ValueError, match="whole number of words"):
        reverse_bytes_in_words(range(31))
