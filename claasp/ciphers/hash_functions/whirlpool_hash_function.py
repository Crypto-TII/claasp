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
from claasp.name_mappings import INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [{'word_size': 8, 'state_size': 8, 'number_of_rounds': 10}]


class WhirlpoolHashFunction(Cipher):

    """
    Returns a cipher object of Whirlpool hash function.

     .. WARNING::

        This cipher handles just the Graph Representation of 1 block input.

    INPUT :

        - 'word_size' -- **integer** (default : '8') the size of the word
        - 'state_size' -- **integer** (default : '8') the number of columns/rows of the internal state matrix
        - 'number_of_rounds' -- **integer** (default: '10') the number of rounds

    EXAMPLES :
        sage: from claasp.ciphers.hash_functions.whirlpool_hash_function import WhirlpoolHashFunction
        sage: whirlpool = WhirlpoolHashFunction()
        sage: key = 0x61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018
        sage: ciphertext = 0x4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5
        sage: whirlpool.evaluate([key]) == ciphertext
        True
    """

    def __init__(self, number_of_rounds=10, word_size=8, state_size=8):

        self.CIPHER_BLOCK_SIZE = state_size ** 2 * word_size
        self.KEY_BLOCK_SIZE = self.CIPHER_BLOCK_SIZE
        self.NUM_SBOXES = state_size ** 2
        self.NROUNDS = number_of_rounds
        self.SBOX_BIT_SIZE = word_size
        self.NUM_COLUMNS = state_size
        self.COLUMN_SIZE = state_size * word_size
        self.NUM_ROWS = self.NUM_COLUMNS
        self.ROW_SIZE = self.COLUMN_SIZE
        self.irreducible_polynomial = 0x11d

        # This is the transpose of the actual Whirlpool matrix. We use this instead of the regular matrix
        # due to the use of MixColumn components to replicate the MixRow operation

        self.WHIRLPOOL_matrix = [[0x01, 0x09, 0x02, 0x05, 0x08, 0x01, 0x04, 0x01],
                                 [0x01, 0x01, 0x09, 0x02, 0x05, 0x08, 0x01, 0x04],
                                 [0x04, 0x01, 0x01, 0x09, 0x02, 0x05, 0x08, 0x01],
                                 [0x01, 0x04, 0x01, 0x01, 0x09, 0x02, 0x05, 0x08],
                                 [0x08, 0x01, 0x04, 0x01, 0x01, 0x09, 0x02, 0x05],
                                 [0x05, 0x08, 0x01, 0x04, 0x01, 0x01, 0x09, 0x02],
                                 [0x02, 0x05, 0x08, 0x01, 0x04, 0x01, 0x01, 0x09],
                                 [0x09, 0x02, 0x05, 0x08, 0x01, 0x04, 0x01, 0x01]]

        self.WHIRLPOOL_matrix_description = [self.WHIRLPOOL_matrix, self.irreducible_polynomial, word_size]

        super().__init__(family_name="whirlpool_hash_function",
                         cipher_type="hash_function",
                         cipher_inputs=[INPUT_KEY],
                         cipher_inputs_bit_size=[self.CIPHER_BLOCK_SIZE],
                         cipher_output_bit_size=self.CIPHER_BLOCK_SIZE)

        self.sbox = [
            0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
            0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
            0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
            0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
            0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
            0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
            0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
            0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
            0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
            0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
            0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
            0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
            0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
            0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
            0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
            0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86

        ]

        # self.ROUND_CONSTANT = [ S[8(r-1)+j] for j in range(8) ] + [0x00 for _ in range(56)]

        self.add_round()

        round_key = self.add_constant_component(self.CIPHER_BLOCK_SIZE, 0x00)  # Initial Key value

        add_round_key = self.add_XOR_component([INPUT_KEY, round_key.id],
                                               [[i for i in range(self.CIPHER_BLOCK_SIZE)],
                                                [i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                               self.CIPHER_BLOCK_SIZE)

        self.add_intermediate_output_component([add_round_key.id],
                                               [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                               self.CIPHER_BLOCK_SIZE,
                                               "round_output")

        add_round_constant = round_key
        for round_number in range(number_of_rounds):
            sboxes_components = self.create_SBOX_component(add_round_key)
            shift_column_components = self.create_shift_column_components(sboxes_components, word_size)
            mix_row_components = self.create_mix_row_components(shift_column_components)

            round_constant = self.create_round_constant_component(round_number)
            key_sboxes_components = self.create_SBOX_component(add_round_constant)
            key_shift_column_components = self.create_shift_column_components(key_sboxes_components, word_size)
            key_mix_row_components = self.create_mix_row_components(key_shift_column_components)

            add_round_constant = self.add_XOR_component(
                [key_mix_row_components[i].id for i in range(self.NUM_COLUMNS)] + [round_constant.id],
                [[i for i in range(self.COLUMN_SIZE)] for _ in range(self.NUM_COLUMNS)] + [
                    [i for i in range(self.CIPHER_BLOCK_SIZE)]],
                self.CIPHER_BLOCK_SIZE)

            add_round_key = self.add_XOR_component(
                [mix_row_components[i].id for i in range(self.NUM_COLUMNS)] + [add_round_constant.id],
                [[i for i in range(self.COLUMN_SIZE)] for _ in range(self.NUM_COLUMNS)] + [
                    [i for i in range(self.CIPHER_BLOCK_SIZE)]],
                self.CIPHER_BLOCK_SIZE)

            self.add_intermediate_output_component([add_round_constant.id],
                                                   [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                                   self.CIPHER_BLOCK_SIZE,
                                                   'intermediate_output')
            if round_number != number_of_rounds -1:
                self.add_round()


        output = self.add_XOR_component([INPUT_KEY, add_round_key.id],
                                        [[i for i in range(self.CIPHER_BLOCK_SIZE)] for _ in range(2)],
                                        self.CIPHER_BLOCK_SIZE)

        self.add_cipher_output_component([output.id],
                                         [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                         self.CIPHER_BLOCK_SIZE)

    def create_SBOX_component(self, add_round_key):
        sboxes_components = []
        for j in range(self.NUM_SBOXES):
            sbox = self.add_SBOX_component(
                [add_round_key.id],
                [[i for i in range(j * self.SBOX_BIT_SIZE, (j + 1) * self.SBOX_BIT_SIZE)]],
                self.SBOX_BIT_SIZE, self.sbox)

            sboxes_components.append(sbox)
        return sboxes_components

    def create_shift_column_components(self, sboxes_components, word_size):
        shift_column_components = []
        for j in range(self.NUM_COLUMNS):
            rotation = self.add_rotate_component(
                [sboxes_components[i].id for i in
                 range(j, j + self.NUM_COLUMNS * (self.NUM_COLUMNS - 1) + 1, self.NUM_COLUMNS)],
                [[i for i in range(self.SBOX_BIT_SIZE)] for _ in range(self.NUM_COLUMNS)],
                self.COLUMN_SIZE,
                word_size * j)
            shift_column_components.append(rotation)

        return shift_column_components

    def create_mix_row_components(self, shift_column_components):
        mix_row_components = []
        for j in range(self.NUM_ROWS):
            mix_row = self.add_mix_column_component(
                [shift_column_components[i].id for i in range(self.NUM_ROWS)],
                [[i for i in range(j * self.NUM_ROWS, (j + 1) * self.NUM_ROWS)] for _ in range(self.NUM_ROWS)],
                self.ROW_SIZE,
                self.WHIRLPOOL_matrix_description)
            mix_row_components.append(mix_row)
        return mix_row_components

    def create_round_constant_component(self, round_number):

        round_constant_value = ['0x'] + [format(self.sbox[8 * (round_number) + j], '02x') for j in
                                         range(8)] + ['00' for _ in range(56)]

        round_constant_string = ('').join(round_constant_value)
        round_constant_hex_value = int(round_constant_string, 16)
        round_constant = self.add_constant_component(self.CIPHER_BLOCK_SIZE, round_constant_hex_value)
        return round_constant
