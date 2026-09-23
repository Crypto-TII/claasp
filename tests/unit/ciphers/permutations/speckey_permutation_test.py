"""Unit tests for Speckey permutation.

REFERENCES:
The standalone Speckey permutation has no explicit test vectors in
[DPUVGB2016]_. The vectors below were derived from the official SPARX
reference implementation [CryptoLUXSPARX]_, using the function A,
which implements one keyless round of SPECK-32.
"""

import pytest

from claasp.ciphers.permutations.speckey_permutation import SpeckeyPermutation


def test_speckey_permutation_reference_vectors():
    speckey = SpeckeyPermutation()

    vectors = [
        (0x00112233, 0x4433CCFF),
        (0x12345678, 0xBE9CE77D),
        (0xFFFF0000, 0xFFFFFFFF),
        (0x01234567, 0x8B699EF4),
    ]

    for permutation_input, expected_output in vectors:
        assert speckey.evaluate(
            [permutation_input],
            verbosity=False,
        ) == expected_output


def test_speckey_invalid_rounds_non_integer_raises():
    with pytest.raises(ValueError, match="number_of_rounds must be > 0"):
        SpeckeyPermutation(number_of_rounds=1.5)


def test_speckey_invalid_rounds_non_positive_raises():
    with pytest.raises(ValueError, match="number_of_rounds must be > 0"):
        SpeckeyPermutation(number_of_rounds=0)


def test_speckey_permutation_reduced_rounds():
    speckey = SpeckeyPermutation(number_of_rounds=3)

    assert speckey.evaluate(
        [0x00112233],
        verbosity=False,
    ) == 0x0EDF0F3F
