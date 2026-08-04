# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************

"""Unit tests for the Serpent block cipher.

REFERENCES:

Anderson, R., Biham, E., & Knudsen, L. (1998). Serpent: A Proposal for
the Advanced Encryption Standard.
"""

import pytest

from claasp.ciphers.block_ciphers.serpent_block_cipher import (
    SerpentBlockCipher,
)


SERPENT_TEST_VECTORS = [
    (
        128,
        0x80000000000000000000000000000000,
        0x00000000000000000000000000000000,
        0x264E5481EFF42A4606ABDA06C0BFDA3D,
    ),
    (
        192,
        0x800000000000000000000000000000000000000000000000,
        0x00000000000000000000000000000000,
        0x9E274EAD9B737BB21EFCFCA548602689,
    ),
    (
        256,
        0x8000000000000000000000000000000000000000000000000000000000000000,
        0x00000000000000000000000000000000,
        0xA223AA1288463C0E2BE38EBD825616C0,
    ),
]

SERPENT_TEST_IDS = [
    "serpent_128_test_vector",
    "serpent_192_test_vector",
    "serpent_256_test_vector",
]


class TestSerpentBlockCipher:
    """Test class for the Serpent block cipher."""

    def test_serpent_default_construction(self):
        """Test the default Serpent configuration."""
        serpent = SerpentBlockCipher()

        assert serpent.type == "block_cipher"
        assert serpent.family_name == "serpent"
        assert serpent.number_of_rounds == 32
        assert serpent.id == "serpent_k256_p128_o128_r32"

    @pytest.mark.parametrize(
        "key_bit_size,key,plaintext,expected_ciphertext",
        SERPENT_TEST_VECTORS,
        ids=SERPENT_TEST_IDS,
    )
    def test_serpent_test_vectors(
        self,
        key_bit_size,
        key,
        plaintext,
        expected_ciphertext,
    ):
        """Validate official Serpent test vectors."""
        serpent = SerpentBlockCipher(key_bit_size=key_bit_size)

        assert serpent.evaluate([key, plaintext]) == expected_ciphertext

    @pytest.mark.parametrize(
        "key_bit_size,key,plaintext,expected_ciphertext",
        SERPENT_TEST_VECTORS,
        ids=SERPENT_TEST_IDS,
    )
    def test_serpent_vectorized_evaluation(
        self,
        key_bit_size,
        key,
        plaintext,
        expected_ciphertext,
    ):
        """Validate Serpent using the vectorized evaluator."""
        serpent = SerpentBlockCipher(key_bit_size=key_bit_size)

        assert (
            serpent.evaluate_vectorized(
                [key, plaintext],
                evaluate_api=True,
            )
            == expected_ciphertext
        )

    def test_serpent_reduced_rounds(self):
        """Test construction of a reduced-round Serpent instance."""
        serpent = SerpentBlockCipher(number_of_rounds=16)

        assert serpent.number_of_rounds == 16
        assert serpent.id == "serpent_k256_p128_o128_r16"

    @pytest.mark.parametrize("key_bit_size", [0, 64, 160, 512])
    def test_serpent_invalid_key_size(self, key_bit_size):
        """Test that unsupported key sizes raise ValueError."""
        with pytest.raises(ValueError):
            SerpentBlockCipher(key_bit_size=key_bit_size)

    @pytest.mark.parametrize("number_of_rounds", [0, 33])
    def test_serpent_invalid_number_of_rounds(self, number_of_rounds):
        """Test that invalid round counts raise ValueError."""
        with pytest.raises(ValueError):
            SerpentBlockCipher(number_of_rounds=number_of_rounds)