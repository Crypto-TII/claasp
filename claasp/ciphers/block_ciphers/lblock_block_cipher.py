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
from claasp.utils.utils import get_ith_word
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

input_types = [INPUT_KEY, INPUT_PLAINTEXT]
PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 64, 'key_bit_size': 80, 'number_of_rounds': 32}]


class LBlockBlockCipher(Cipher):
    """
    Construct an instance of the LBlockBlockCipher class.

    This class is used to store compact representations of a cipher,
    used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``sub_keys_zero`` -- **boolean** (default: `False`)
    - ``transformations_flag`` -- **boolean** (default: `True`)

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
        sage: lblock = LBlockBlockCipher(number_of_rounds=32)
        sage: lblock.evaluate([0,0])
        13985955387709807565
    """

    def __init__(self, number_of_rounds=32):
        self.block_bit_size = 64
        self.key_bit_size = 80
        self.WORD_SIZE = 32
        self.SBOXES = {0: [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5],
                       1: [4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3],
                       2: [1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10],
                       3: [7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1],
                       4: [14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3],
                       5: [2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5],
                       6: [11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2],
                       7: [13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6],
                       8: [8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3],
                       9: [11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6]
                       }
        super().__init__(family_name="lblock",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        state = INPUT_PLAINTEXT
        key = INPUT_KEY

        for round_i in range(1, number_of_rounds + 1):
            self.add_round()
            round_key = self.add_round_key_output_component([key], [list(range(32))], 32).id  #
            state = self.round_function(state, round_key)
            key = self.update_key(key, round_i)
        self.add_cipher_output_component([state, state], [list(range(32, 64)), list(range(32))], 64)

    def update_key(self, k, i):
        rot_k = self.add_rotate_component([k], [list(range(80))], 80, -29).id  #
        s0 = self.add_SBOX_component([rot_k], [list(range(4))], 4, self.SBOXES[9]).id  #
        s1 = self.add_SBOX_component([rot_k], [list(range(4, 8))], 4, self.SBOXES[8]).id  #
        c0 = self.add_constant_component(5, i).id
        xor0 = self.add_XOR_component([rot_k, c0], [[29, 30, 31, 32, 33], list(range(5))], 5).id  #
        updated_key = self.add_intermediate_output_component([s0, s1, rot_k, xor0, rot_k],
                                                             [list(range(4)), list(range(4)), list(range(8, 29)),
                                                              list(range(5)), list(range(34, 80))], 80, 'updated_key')
        return updated_key.id

    def round_function(self, x, k):
        word_pos = [1, 3, 0, 2, 5, 7, 4, 6]
        sb_order = [6, 4, 7, 5, 2, 0, 3, 1]
        after_key_add = self.add_XOR_component([x, k], [list(range(32))] + [list(range(32))], 32).id
        sb_outputs = [self.add_SBOX_component([after_key_add], [list(range(word_pos[i] * 4, (word_pos[i] + 1) * 4))], 4,
                                              self.SBOXES[sb_order[i]]).id for i in range(8)]
        right_word_rotated = self.add_rotate_component([x], [list(range(32, 64))], 32, -8).id
        new_left_word = self.add_XOR_component(sb_outputs + [right_word_rotated],
                                               [list(range(4)) for i in range(8)] + [list(range(32))], 32).id
        round_output = self.add_round_output_component([new_left_word, x], [list(range(32)), list(range(32))], 64).id
        return round_output
