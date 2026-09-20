import pytest

from claasp import bits_from_int, int_from_bits


def test_integer_bit_conversion_is_msb_first_and_round_trips():
    assert bits_from_int(0xA5, 8) == (1, 0, 1, 0, 0, 1, 0, 1)
    assert int_from_bits(bits_from_int(0x1234, 16)) == 0x1234


def test_integer_bit_conversion_rejects_truncation():
    with pytest.raises(ValueError, match="fit in 8 bits"):
        bits_from_int(256, 8)


def test_bit_decoding_requires_integer_bits():
    with pytest.raises(ValueError, match="zeroes and ones"):
        int_from_bits((0, True))
