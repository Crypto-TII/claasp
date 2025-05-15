
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
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import get_number_of_rounds_from
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 6, 'key_bit_size': 6, 'number_of_rounds': 2}
]


class ToySPN2(Cipher):
    """
    Construct an instance of the ToySPN2 class.
    This class is used to implement a family of small toy ciphers,
    the smallest of which has 6-bit block and key size.
    The key schedule performs a key rotation at every round.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `6`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `6`); cipher key bit size of the cipher
    - ``rotation_layer`` -- **integer** (default: `1`)
    - ``round_key_rotation`` -- **integer** (default: `1`)
    - ``sbox`` -- **integer list** (default: [0, 5, 3, 2, 6, 1, 4, 7]); lookup table of the S-box. The default is Xoodoo 3-bit S-box.
    - ``number_of_rounds`` -- **integer** (default: `10`); number of rounds of the cipher.

    EXAMPLES::

        sage: from claasp.ciphers.toys.toyspn2 import ToySPN2
        sage: toyspn2 = ToySPN2()
        sage: toyspn2.number_of_rounds
        2
        sage: hex(toyspn2.evaluate([0x3F, 0x01], verbosity=True))
        <BLANKLINE>
        Round_0
        <BLANKLINE>
        rot_0_0_input = 0b000001
        rot_0_0_output = 0b100000
        intermediate_output_0_1_input = 0b100000
        intermediate_output_0_1_output = 0b100000
        xor_0_2_input = 0xfe0
        xor_0_2_output = 0b011111
        sbox_0_3_input = 0b011
        sbox_0_3_output = 0b010
        sbox_0_4_input = 0b111
        sbox_0_4_output = 0b111
        rot_0_5_input = 0b010111
        rot_0_5_output = 0b101011
        intermediate_output_0_6_input = 0b101011
        intermediate_output_0_6_output = 0b101011
        <BLANKLINE>
        Round_1
        <BLANKLINE>
        rot_1_0_input = 0b100000
        rot_1_0_output = 0b010000
        intermediate_output_1_1_input = 0b010000
        intermediate_output_1_1_output = 0b010000
        xor_1_2_input = 0xad0
        xor_1_2_output = 0b111011
        sbox_1_3_input = 0b111
        sbox_1_3_output = 0b111
        sbox_1_4_input = 0b011
        sbox_1_4_output = 0b010
        rot_1_5_input = 0b111010
        rot_1_5_output = 0b011101
        intermediate_output_1_6_input = 0b011101
        intermediate_output_1_6_output = 0b011101
        cipher_output_1_7_input = 0b011101
        cipher_output_1_7_output = 0b011101
        '0x1d'

    """
    def __init__(self,
                 block_bit_size=6,
                 key_bit_size=6,
                 rotation_layer=1,
                 round_key_rotation=1,
                 sbox = [0, 5, 3, 2, 6, 1, 4, 7], # Xoodoo S-box
                 number_of_rounds=2):
        self.sbox_bit_size = len(bin(len(sbox)))-3
        self.number_of_sboxes = block_bit_size // self.sbox_bit_size
        super().__init__(family_name="toyspn1",
                         cipher_type=BLOCK_CIPHER,
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size)

        xor_input1 = INPUT_PLAINTEXT
        round_key_id = INPUT_KEY

        for _ in range(number_of_rounds):
            self.add_round()

            # Key rotation
            round_key = self.add_rotate_component([round_key_id], [[i for i in range(key_bit_size)]], key_bit_size, round_key_rotation)

            self.add_round_key_output_component([round_key.id], [[i for i in range(key_bit_size)]], key_bit_size)

            # XOR with round key
            xor = self.add_XOR_component(
                 [xor_input1] + [round_key.id],
                 [[i for i in range(block_bit_size)],
                  [i for i in range(block_bit_size)]],
                 block_bit_size)

            # S-box layer
            sbox_ids_list = []
            for ns in range(self.number_of_sboxes):
                sbox_component = self.add_SBOX_component([xor.id],
                                        [[ns*self.sbox_bit_size + i for i in range(self.sbox_bit_size)]],
                                        self.sbox_bit_size,
                                        sbox)
                sbox_ids_list.append(sbox_component.id)

            # ROTATION layer
            rotate_component = self.add_rotate_component(
                sbox_ids_list,
                [[i for i in range(self.sbox_bit_size)] for _ in range(self.number_of_sboxes)],
                block_bit_size,
                rotation_layer)

            self.add_round_output_component([rotate_component.id],
                                            [[i for i in range(block_bit_size)]],
                                            block_bit_size)

            # update input to next round
            xor_input1 = rotate_component.id
            round_key_id = round_key.id

        self.add_cipher_output_component(
            [rotate_component.id],
            [[i for i in range(block_bit_size)]],
            block_bit_size)