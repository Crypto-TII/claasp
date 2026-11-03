"""Retain published vectors from four previously uninventoried legacy primitives."""

import pytest

from claasp.primitives import CRAX, RC6, Alzette, Blowfish
from claasp.primitives.block_ciphers.rc6 import rc6_magic_constants


@pytest.mark.parametrize(
    "parameters,inputs,expected",
    [
        (
            {},
            (0x02132435465768798A9BACBDCEDFE0F1, 0x0123456789ABCDEF0112233445566778),
            0x524E192F4715C6231F51F6367EA43F18,
        ),
        (
            {"key_bit_size": 256},
            (
                0x02132435465768798A9BACBDCEDFE0F1,
                0x0123456789ABCDEF0112233445566778899AABBCCDDEEFF01032547698BADCFE,
            ),
            0xC8241816F0D7E48920AD16A1674E5D48,
        ),
        (
            {"word_size": 8, "key_bit_size": 32, "number_of_rounds": 12},
            (0x00010203, 0x00010203),
            0xAEFC4612,
        ),
    ],
)
def test_rc6_published_vectors(parameters, inputs, expected):
    """RC6 v1.1 appendix and draft-krovetz-rc6-rc5-vectors-00 §3."""
    assert RC6(**parameters).evaluate(*inputs) == expected


@pytest.mark.parametrize(
    "plaintext,key,expected",
    [
        (0, 0, 0x72EDFAC9453F5F4C),
        (0x3322110077665544, 0x03020100070605040B0A09080F0E0D0C, 0x6203C5BE7AE77255),
    ],
)
def test_crax_reference_vectors(plaintext, key, expected):
    """Designers' CRAX-S reference vectors retained from legacy tests."""
    assert CRAX().evaluate(plaintext, key) == expected


@pytest.mark.parametrize(
    "parameters,plaintext,expected",
    [
        ({}, 0, 0x44DD4DE9E5581F2D),
        ({}, 0xDEADBEEFCAFEBABE, 0x9D50490C3A596770),
        ({"round_constant": 0xBF715880}, 0x0123456789ABCDEF, 0x6AA7EB426BCD187D),
    ],
)
def test_alzette_reference_vectors(parameters, plaintext, expected):
    """SPARKLE ARXBOX reference vectors retained from legacy tests."""
    assert Alzette(**parameters).evaluate(plaintext) == expected


@pytest.mark.parametrize(
    "key,bits,plaintext,expected",
    [
        (0, 64, 0, 0x4EF997456198DD78),
        (0xFFFFFFFFFFFFFFFF, 64, 0xFFFFFFFFFFFFFFFF, 0x51866FD5B85ECB8A),
        (0x3000000000000000, 64, 0x1000000000000001, 0x7D856F9A613063F2),
        (0x1111111111111111, 64, 0x1111111111111111, 0x2466DD878B963C9D),
        (0x0123456789ABCDEF, 64, 0x1111111111111111, 0x61F9C3802281B096),
        (0x1111111111111111, 64, 0x0123456789ABCDEF, 0x7D0CC630AFDA1EC7),
        (0xF0E1D2C3, 32, 0xFEDCBA9876543210, 0xBE1E639408640F05),
        (0xF0E1D2C3B4A59687, 64, 0xFEDCBA9876543210, 0xE87A244E2CC85E82),
        (0xF0E1D2C3B4A5968778695A4B3C2D1E0F, 128, 0xFEDCBA9876543210, 0x93142887EE3BE15C),
    ],
)
def test_blowfish_official_vectors(key, bits, plaintext, expected):
    """Schneier's vectors-2.txt; key expansion occurs at construction."""
    assert Blowfish(key=key, key_bit_size=bits).evaluate(plaintext) == expected


@pytest.mark.parametrize("bits", [24, 456])
def test_blowfish_invalid_key_width(bits):
    with pytest.raises(ValueError, match="between 32 and 448 bits"):
        Blowfish(key_bit_size=bits)


def test_rc6_constants():
    assert rc6_magic_constants(32) == (0xB7E15163, 0x9E3779B9)
