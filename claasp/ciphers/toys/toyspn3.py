
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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 6, 'key_bit_size': 12, 'number_of_rounds': 2}
]


class ToySPN3(Cipher):
    """
    Construct an instance of the ToySPN1 class.
    This class is used to implement a family of small toy ciphers,
    the smallest of which has 6-bit block and key size.
    This toy block cipher has not key schedule, i.e. the key is the same at every round.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `6`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `6`); cipher key bit size of the cipher
    - ``rotation_layer`` -- **integer** (default: `1`)
    - ``sbox`` -- **integer list** (default: [0, 5, 3, 2, 6, 1, 4, 7]); lookup table of the S-box. The default is Xoodoo 3-bit S-box.
    - ``number_of_rounds`` -- **integer** (default: `10`); number of rounds of the cipher.

    EXAMPLES::

        sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
        sage: toyspn1 = ToySPN1()
        sage: toyspn1.number_of_rounds
        2
        sage: plaintext = 0x3F; key = 0x3F
        sage: ciphertext = 0x3F
        sage: toyspn1.evaluate([plaintext, key]) == ciphertext
        True
        sage: hex(toyspn1.evaluate([plaintext, key]))
        '0x3f'
        sage: hex(toyspn1.evaluate([0x3F, 0x3E], verbosity=True))
        <BLANKLINE>
        Round_0
        <BLANKLINE>
        intermediate_output_0_0_input = 0b111110
        intermediate_output_0_0_output = 0b111110
        xor_0_1_input = 0xffe
        xor_0_1_output = 0b000001
        sbox_0_2_input = 0b000
        sbox_0_2_output = 0b000
        sbox_0_3_input = 0b001
        sbox_0_3_output = 0b101
        rot_0_4_input = 0b000101
        rot_0_4_output = 0b100010
        intermediate_output_0_5_input = 0b100010
        intermediate_output_0_5_output = 0b100010
        <BLANKLINE>
        Round_1
        <BLANKLINE>
        intermediate_output_1_0_input = 0b111110
        intermediate_output_1_0_output = 0b111110
        xor_1_1_input = 0x8be
        xor_1_1_output = 0b011100
        sbox_1_2_input = 0b011
        sbox_1_2_output = 0b010
        sbox_1_3_input = 0b100
        sbox_1_3_output = 0b110
        rot_1_4_input = 0b010110
        rot_1_4_output = 0b001011
        intermediate_output_1_5_input = 0b001011
        intermediate_output_1_5_output = 0b001011
        cipher_output_1_6_input = 0b001011
        cipher_output_1_6_output = 0b001011
        '0xb'
        sage: toyspn1 = ToySPN1(block_bit_size=9, key_bit_size=9, number_of_rounds=10)
        sage: hex(toyspn1.evaluate([0x1FF, 0x1FE]))
        '0x173'
        sage: toyspn1 = ToySPN1(block_bit_size=8, key_bit_size=8, sbox=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0], rotation_layer=-2, number_of_rounds=10)
        sage: hex(toyspn1.evaluate([0xFF, 0xFE]))
        '0x6c'

    """
    def __init__(self,
                 block_bit_size=6,
                 rotation_layer=1,
                 sbox = [0, 5, 3, 2, 6, 1, 4, 7], # Xoodoo S-box
                 number_of_rounds=2):
        self.key_bit_size = block_bit_size * number_of_rounds
        self.sbox_bit_size = len(bin(len(sbox)))-3
        self.number_of_sboxes = block_bit_size // self.sbox_bit_size
        super().__init__(family_name="toyspn1",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=block_bit_size)

        xor_input1 = INPUT_PLAINTEXT
        xor_input2 = INPUT_KEY
        for r in range(number_of_rounds):
            self.add_round()

            self.add_round_key_output_component([INPUT_KEY], [[i for i in range(r * block_bit_size, (r+1) * block_bit_size)]], block_bit_size)

            # XOR with round key
            xor = self.add_XOR_component(
                 [xor_input1] + [xor_input2],
                 [[i for i in range(block_bit_size)],
                  [i for i in range(r * block_bit_size, (r+1) * block_bit_size)]],
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

            xor_input1 = rotate_component.id
            xor_input2 = INPUT_KEY

        self.add_cipher_output_component(
            [rotate_component.id],
            [[i for i in range(block_bit_size)]],
            block_bit_size)
