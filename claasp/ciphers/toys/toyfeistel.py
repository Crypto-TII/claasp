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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 8, 'self.key_bit_size': 8, 'number_of_rounds': 5}
]


class ToyFeistel(Cipher):
    """
    Construct an instance of the ToyFeistel class.
    This class is used to implement a family of small toy ciphers,
    the smallest of which has 8-bit block and key size.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `8`); cipher input and output block bit size of the cipher
    - ``self.key_bit_size`` -- **integer** (default: `8`); cipher key bit size of the cipher
    - ``sbox`` -- **integer list** (default: [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5]); lookup table of the S-box. The default is the 4-bit S-box S_0 from LBlock.
    - ``number_of_rounds`` -- **integer** (default: `5`); number of rounds of the cipher.

    EXAMPLES::

        sage: from claasp.ciphers.toys.toyfeistel import ToyFeistel
        sage: toyfeistel = ToyFeistel()
        sage: toyfeistel.number_of_rounds
        5
        sage: plaintext = 0x3F; key = 0x3F
        sage: ciphertext = 0x8e
        sage: toyfeistel.evaluate([plaintext, key]) == ciphertext
        True
        sage: hex(toyfeistel.evaluate([plaintext, key]))
        '0x8e'
    """

    def __init__(self,
                 block_bit_size=8,
                 key_bit_size=8,
                 sbox=[14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5],  # LBLOCK S-box_0
                 number_of_rounds=5):
        self.sbox = sbox
        self.sbox_bit_size = len(bin(len(sbox))) - 3
        self.number_of_sboxes = block_bit_size // self.sbox_bit_size
        self.key_bit_size = key_bit_size
        self.block_bit_size = block_bit_size

        super().__init__(family_name="toyfeistel",
                         cipher_type=BLOCK_CIPHER,
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size)

        state = INPUT_PLAINTEXT
        key = INPUT_KEY

        for round_i in range(1, number_of_rounds + 1):
            self.add_round()
            round_key = self.add_round_key_output_component([key], [list(range(self.block_bit_size // 2))],
                                                            self.block_bit_size // 2).id
            state = self.round_function(state, round_key)
            key = self.update_key(key, round_i)
        self.add_cipher_output_component([state, state], [list(range(self.block_bit_size // 2, self.block_bit_size)),
                                                          list(range(self.block_bit_size // 2))], self.block_bit_size)

    def update_key(self, k, i):
        rot_5 = self.add_rotate_component([k], [list(range(self.key_bit_size))], self.key_bit_size, -5).id
        xor0 = self.add_XOR_component([k, rot_5], [list(range(self.key_bit_size)), list(range(self.key_bit_size))],
                                      self.key_bit_size).id
        c0 = self.add_constant_component(self.key_bit_size // 2, i).id
        xor1 = self.add_XOR_component([xor0, c0], [list(range(self.key_bit_size // 2, self.key_bit_size)),
                                                   list(range(self.key_bit_size // 2))], self.key_bit_size // 2).id  #
        updated_key = self.add_intermediate_output_component([xor0, xor1],
                                                             [list(range(self.key_bit_size // 2)),
                                                              list(range(self.key_bit_size // 2))], self.key_bit_size,
                                                             'updated_key')
        return updated_key.id

    def round_function(self, state, key):
        right_half_positions = list(range(self.block_bit_size // 2, self.block_bit_size))
        after_key_add = self.add_XOR_component([state, key],
                                               [right_half_positions, list(range(self.block_bit_size // 2))],
                                               self.block_bit_size // 2).id
        sb_output = self.add_SBOX_component([after_key_add], [list(range(self.block_bit_size // 2))],
                                            self.block_bit_size // 2,
                                            self.sbox).id
        new_right_word = self.add_XOR_component([sb_output, state],
                                                [list(range(self.block_bit_size // 2))] + [
                                                    list(range(self.block_bit_size // 2))], self.block_bit_size // 2).id
        round_output = self.add_round_output_component([state, new_right_word],
                                                       [right_half_positions, list(range(self.block_bit_size // 2))],
                                                       self.block_bit_size).id
        return round_output
