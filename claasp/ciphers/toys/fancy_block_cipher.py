
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

PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 24, 'key_bit_size': 24, 'number_of_rounds': 20}]


class FancyBlockCipher(Cipher):
    """
    Return a cipher object containing the graph representation the Fancy Block Cipher.

    The Fancy Block Cipher is not meant to be a secure cipher,
    but was created for testing purposes, and it includes several weaknesses by definition.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `24`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `24`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `20`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
        sage: fancy = FancyBlockCipher()
        sage: fancy.number_of_rounds
        20

        sage: fancy.component_from(0, 0).id
        'sbox_0_0'
    """

    def __init__(self, block_bit_size=24, key_bit_size=24, number_of_rounds=20):
        super().__init__(family_name="fancy_block_cipher",
                         cipher_type=BLOCK_CIPHER,
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size)

        self.LINEAR_LAYER = [
            [0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1],
            [0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1],
            [1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1],
            [1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1],
            [1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0],
            [1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0],
            [1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1],
            [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0],
            [1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1],
            [0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0],
            [0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0],
            [0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0],
            [1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1],
            [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1],
            [0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1],
            [0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
            [0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1],
            [0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1],
            [0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0],
            [1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1],
            [0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1],
            [1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1]
        ]

        self.SBOX_DESCRIPTION = [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
        self.SBOX_BIT_SIZE = 4
        self.NUM_SBOXES = int(block_bit_size / self.SBOX_BIT_SIZE)
        type2_modadd1 = None
        type2_modadd2 = None
        type2_xor1 = None
        type2_xor2 = None
        type2_key_schedule_and = None
        type2_key_schedule_xor = None

        for round_number in range(number_of_rounds):
            self.add_round()
            is_an_even_round = (round_number % 2) == 0
            if is_an_even_round:
                type1_sboxes = []
                self.add_sbox_components_layer_in_even_rounds(round_number, type1_sboxes, type2_modadd1,
                                                              type2_modadd2, type2_xor1, type2_xor2)
                input_link_ids = self.collect_input_id_links(type1_sboxes)
                linear_layer = self.add_linear_layer_component(input_link_ids,
                                                               [list(range(self.SBOX_BIT_SIZE)) for _ in
                                                                range(self.NUM_SBOXES)], block_bit_size,
                                                               self.LINEAR_LAYER)
                type1_key_schedule_xor = self.add_xor_component_to_even_round(key_bit_size,
                                                                              round_number,
                                                                              type2_key_schedule_and,
                                                                              type2_key_schedule_xor)
                type1_key_schedule_and = self.add_and_component_to_even_round(key_bit_size,
                                                                              round_number,
                                                                              type1_key_schedule_xor,
                                                                              type2_key_schedule_and)
                self.add_intermediate_output_component([type1_key_schedule_xor.id, type1_key_schedule_and.id],
                                                       [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                                                        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]],
                                                       key_bit_size,
                                                       "round_key_output")
                constant = self.add_constant_component(block_bit_size, 0xFEDCBA)
                type1_xor_with_key = self.add_XOR_component(
                    [constant.id, linear_layer.id, type1_key_schedule_xor.id, type1_key_schedule_and.id],
                    [list(range(block_bit_size)), list(range(block_bit_size)),
                     list(range(int(block_bit_size / 2))), list(range(int(block_bit_size / 2)))],
                    block_bit_size)
                if round_number == number_of_rounds - 1:
                    self.add_cipher_output_component([type1_xor_with_key.id],
                                                     [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                                       13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]],
                                                     block_bit_size)
                else:
                    self.add_intermediate_output_component([type1_xor_with_key.id],
                                                           [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                                             13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]],
                                                           block_bit_size,
                                                           "round_output")

            else:
                b = self.SBOX_BIT_SIZE
                type2_sboxes = []
                for j in range(self.NUM_SBOXES):
                    sbox = self.add_SBOX_component([type1_xor_with_key.id], [list(range(j * b + 0, j * b + b))],
                                                   b, self.SBOX_DESCRIPTION)
                    type2_sboxes.append(sbox)

                # key schedule for type 2 round
                type2_key_schedule_xor = self.add_XOR_component(
                    [type1_key_schedule_xor.id, type1_key_schedule_and.id],
                    [list(range(int(key_bit_size / 2))), list(range(int(key_bit_size / 2)))],
                    int(key_bit_size / 2))
                type2_key_schedule_and = self.add_AND_component([type2_key_schedule_xor.id, type1_key_schedule_and.id],
                                                                [list(range(int(key_bit_size / 2))) for _ in range(2)],
                                                                int(key_bit_size / 2))
                self.add_intermediate_output_component([type2_key_schedule_xor.id, type2_key_schedule_and.id],
                                                       [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                                                        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]],
                                                       key_bit_size,
                                                       "round_key_output")

                # Modular addition 8
                type2_modadd1 = self.add_MODADD_component(
                    [type2_key_schedule_xor.id, type2_sboxes[0].id,
                        type2_sboxes[1].id, type2_sboxes[1].id, type2_sboxes[3].id],
                    [list(range(int(block_bit_size / 4))),
                     list(range(self.SBOX_BIT_SIZE)), list(range(int(self.SBOX_BIT_SIZE / 2))),
                     list(range(int(self.SBOX_BIT_SIZE / 2), self.SBOX_BIT_SIZE)), list(range(self.SBOX_BIT_SIZE))],
                    int(block_bit_size / 4))

                # Modular addition 9
                type2_modadd2 = self.add_MODADD_component(
                    [type2_key_schedule_xor.id, type2_sboxes[3].id,
                     type2_sboxes[4].id, type2_sboxes[4].id, type2_sboxes[5].id],
                    [list(range(int(block_bit_size / 4), int(block_bit_size / 2))),
                     list(range(self.SBOX_BIT_SIZE)),
                     list(range(int(self.SBOX_BIT_SIZE / 2))),
                     list(range(int(self.SBOX_BIT_SIZE / 2), self.SBOX_BIT_SIZE)),
                     list(range(self.SBOX_BIT_SIZE))],
                    int(block_bit_size / 4))

                # Left rotation_3 10
                rotation = self.add_rotate_component([type2_sboxes[1].id, type2_sboxes[2].id],
                                                     [list(range(int(self.SBOX_BIT_SIZE / 2), self.SBOX_BIT_SIZE)),
                                                      list(range(self.SBOX_BIT_SIZE))],
                                                     int(block_bit_size / 4), -3)

                # Right shift_3 11
                shift = self.add_SHIFT_component([type2_sboxes[4].id, type2_sboxes[5].id],
                                                 [list(range(int(self.SBOX_BIT_SIZE / 2), self.SBOX_BIT_SIZE)),
                                                  list(range(self.SBOX_BIT_SIZE))],
                                                 int(block_bit_size / 4), 3)

                # xor 12
                type2_xor1 = self.add_XOR_component([type2_modadd1.id, rotation.id, type2_key_schedule_and.id],
                                                    [list(range(int(block_bit_size / 4))) for _ in range(3)],
                                                    int(block_bit_size / 4))

                # xor 13
                type2_xor2 = self.add_XOR_component(
                    [type2_modadd2.id, shift.id, type2_key_schedule_and.id],
                    [list(range(int(block_bit_size / 4))), list(range(int(block_bit_size / 4))),
                     list(range(int(block_bit_size / 4), int(block_bit_size / 2)))],
                    int(block_bit_size / 4))

                # add round output component
                if round_number == number_of_rounds - 1:
                    self.add_cipher_output_component(
                        [type2_modadd1.id, type2_xor1.id, type2_modadd2.id, type2_xor2.id],
                        [[0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5]],
                        block_bit_size)
                else:
                    self.add_intermediate_output_component(
                        [type2_modadd1.id, type2_xor1.id, type2_modadd2.id, type2_xor2.id],
                        [[0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5]],
                        block_bit_size, "round_output")

    def add_sbox_components_layer_in_even_rounds(self, round_number, type1_sboxes, type2_modadd1, type2_modadd2,
                                                 type2_xor1, type2_xor2):
        for j in range(self.NUM_SBOXES):
            b = self.SBOX_BIT_SIZE
            if round_number == 0:
                sbox = self.add_SBOX_component([INPUT_PLAINTEXT], [list(range(j * b + 0, j * b + b))], b,
                                               self.SBOX_DESCRIPTION)
            else:
                if j == 0:
                    sbox = self.add_SBOX_component([type2_modadd1.id], [list(range(4))],
                                                   self.SBOX_BIT_SIZE, self.SBOX_DESCRIPTION)
                elif j == 1:
                    sbox = self.add_SBOX_component([type2_modadd1.id, type2_xor1.id],
                                                   [list(range(4, 6)), list(range(2))],
                                                   self.SBOX_BIT_SIZE, self.SBOX_DESCRIPTION)
                elif j == 2:
                    sbox = self.add_SBOX_component([type2_xor1.id], [list(range(2, 6))],
                                                   self.SBOX_BIT_SIZE, self.SBOX_DESCRIPTION)
                elif j == 3:
                    sbox = self.add_SBOX_component([type2_modadd2.id], [list(range(4))],
                                                   self.SBOX_BIT_SIZE, self.SBOX_DESCRIPTION)
                elif j == 4:
                    sbox = self.add_SBOX_component([type2_modadd2.id, type2_xor2.id],
                                                   [list(range(4, 6)), list(range(2))],
                                                   self.SBOX_BIT_SIZE, self.SBOX_DESCRIPTION)
                elif j == 5:
                    sbox = self.add_SBOX_component([type2_xor2.id], [list(range(2, 6))],
                                                   self.SBOX_BIT_SIZE, self.SBOX_DESCRIPTION)
                else:
                    print("Error! undefined assignment to sbox!")
                    sbox = None
            type1_sboxes.append(sbox)

    def add_and_component_to_even_round(self, key_bit_size, round_number,
                                        type1_key_schedule_xor, type2_key_schedule_and):
        if round_number == 0:
            type1_key_schedule_and = self.add_AND_component(
                [type1_key_schedule_xor.id, INPUT_KEY],
                [list(range(int(key_bit_size / 2))),
                 [i + int(key_bit_size / 2) for i in range(int(key_bit_size / 2))]],
                int(key_bit_size / 2))
        else:
            type1_key_schedule_and = self.add_AND_component(
                [type1_key_schedule_xor.id, type2_key_schedule_and.id],
                [list(range(int(key_bit_size / 2))) for _ in range(2)],
                int(key_bit_size / 2))

        return type1_key_schedule_and

    def add_xor_component_to_even_round(self, key_bit_size, round_number,
                                        type2_key_schedule_and, type2_key_schedule_xor):
        if round_number == 0:
            type1_key_schedule_xor = self.add_XOR_component(
                [INPUT_KEY, INPUT_KEY],
                [list(range(int(key_bit_size / 2))), list(range(int(key_bit_size / 2), key_bit_size))],
                int(key_bit_size / 2))
        else:
            type1_key_schedule_xor = self.add_XOR_component(
                [type2_key_schedule_xor.id, type2_key_schedule_and.id],
                [list(range(int(key_bit_size / 2))), list(range(int(key_bit_size / 2)))],
                int(key_bit_size / 2))

        return type1_key_schedule_xor

    def collect_input_id_links(self, type1_sboxes):
        input_link_ids = []
        for j in range(self.NUM_SBOXES):
            input_link_ids.append(type1_sboxes[j].id)

        return input_link_ids
