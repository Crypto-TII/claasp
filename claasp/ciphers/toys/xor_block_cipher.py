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


from claasp.cipher import Cipher


class XorBlockCipher(Cipher):
    """Single-round block cipher that computes plaintext XOR key.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `16`); bit size of both the
      plaintext and the key

    EXAMPLES::

        sage: from claasp.ciphers.toys.xor_block_cipher import XorBlockCipher
        sage: cipher = XorBlockCipher(block_bit_size=8)
        sage: cipher.get_component_from_id("xor_0_0").id
        'xor_0_0'
    """

    def __init__(self, block_bit_size=16):
        if block_bit_size <= 0:
            raise ValueError("block_bit_size must be a positive integer")

        super().__init__(
            family_name="xor_block_cipher",
            cipher_type="block_cipher",
            cipher_inputs=["plaintext", "key"],
            cipher_inputs_bit_size=[block_bit_size, block_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        self.add_round()
        self.add_XOR_component(
            ["plaintext", "key"],
            [list(range(block_bit_size)), list(range(block_bit_size))],
            block_bit_size,
        )
        self.add_cipher_output_component(
            [self.get_all_components()[-1].id],
            [list(range(block_bit_size))],
            block_bit_size,
        )
