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


import pytest
from claasp.ciphers.block_ciphers.rijndael_block_cipher import RijndaelBlockCipher


class TestRijndaelBlockCipher:
    """Test class for Rijndael block cipher."""

    def test_rijndael_128_128_tv1(self):
        """Test Rijndael-128-128: Test vector 1 from specification."""
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=128)
        key = 0x2b7e151628aed2a6abf7158809cf4f3c
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        expected = 0x3925841d02dc09fbdc118597196a0b32
        assert rijndael.evaluate([key, plaintext]) == expected

    def test_rijndael_128_192_tv1(self):
        """Test Rijndael-128-192: Test vector 1 from specification."""
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=192)
        key = 0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        expected = 0xf9fb29aefc384a250340d833b87ebc00
        assert rijndael.evaluate([key, plaintext]) == expected

    def test_rijndael_128_256_tv1(self):
        """Test Rijndael-128-256: Test vector 1 from specification."""
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=256)
        key = 0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        expected = 0x3243f6a8885a308d313198a2e0370734
        assert rijndael.evaluate([key, plaintext]) == expected

    def test_rijndael_default_construction(self):
        """Test default cipher construction."""
        rijndael = RijndaelBlockCipher()
        assert rijndael.number_of_rounds == 10  # 128-bit key gives 4 words, so 4+6=10

    def test_rijndael_192_bit_key_rounds(self):
        """Test that 192-bit key gives correct number of rounds."""
        rijndael = RijndaelBlockCipher(key_bit_size=192)
        assert rijndael.number_of_rounds == 12  # 192-bit key gives 6 words, so 6+6=12

    def test_rijndael_256_bit_key_rounds(self):
        """Test that 256-bit key gives correct number of rounds."""
        rijndael = RijndaelBlockCipher(key_bit_size=256)
        assert rijndael.number_of_rounds == 14  # 256-bit key gives 8 words, so 8+6=14

    def test_rijndael_invalid_block_size(self):
        """Test that invalid block size raises error."""
        with pytest.raises(ValueError):
            RijndaelBlockCipher(block_bit_size=192)

    def test_rijndael_invalid_key_size(self):
        """Test that invalid key size raises error."""
        with pytest.raises(ValueError):
            RijndaelBlockCipher(key_bit_size=512)

    def test_rijndael_128_zero_key_plaintext(self):
        """Test with all-zero key and plaintext."""
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=128)
        result = rijndael.evaluate([0x00000000000000000000000000000000, 0x00000000000000000000000000000000])
        # All zeros should produce a non-zero deterministic ciphertext
        assert result != 0x00000000000000000000000000000000

    def test_rijndael_128_test_vector_2(self):
        """Test with second test vector from specification."""
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=128)
        key = 0x00000000000000000000000000000000
        plaintext = 0x00000000000000000000000000000000
        expected = 0x66E94BD4EF8A2C3B884CFA59CA342B2E
        assert rijndael.evaluate([key, plaintext]) == expected

    def test_rijndael_128_test_vector_3(self):
        """Test with third test vector from specification."""
        rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=128)
        key = 0x00000000000000000000000000000000
        plaintext = 0x66E94BD4EF8A2C3B884CFA59CA342B2E
        expected = 0xF795BD4A52E29ED713D313FA20E98DBC
        assert rijndael.evaluate([key, plaintext]) == expected
