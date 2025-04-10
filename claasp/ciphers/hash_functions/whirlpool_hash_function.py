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
from claasp.name_mappings import INPUT_MESSAGE, INTERMEDIATE_OUTPUT

PARAMETERS_CONFIGURATION_LIST = [{"word_size": 8, "state_size": 8, "number_of_rounds": 10}]


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
        sage: message = 0x61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018
        sage: digest = 0x4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5
        sage: whirlpool.evaluate([message]) == digest
        True
    """

    def __init__(self, number_of_rounds=10, word_size=8, state_size=8):
        self.cipher_block_size = state_size**2 * word_size
        self.key_block_size = self.cipher_block_size
        self.num_sboxes = state_size**2
        self.nrounds = number_of_rounds
        self.sbox_bit_size = word_size
        self.num_columns = state_size
        self.column_size = state_size * word_size
        self.num_rows = self.num_columns
        self.row_size = self.column_size
        self.irreducible_polynomial = 0x11D

        # This is the transpose of the actual Whirlpool matrix. We use this instead of the regular matrix
        # due to the use of MixColumn components to replicate the MixRow operation

        # fmt: off
        self.sbox = [
            0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52,
            0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C, 0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57,
            0x15, 0x77, 0x37, 0xE5, 0x9F, 0xF0, 0x4A, 0xDA, 0x58, 0xC9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85,
            0xBD, 0x5D, 0x10, 0xF4, 0xCB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7D, 0x95, 0xD8,
            0xFB, 0xEE, 0x7C, 0x66, 0xDD, 0x17, 0x47, 0x9E, 0xCA, 0x2D, 0xBF, 0x07, 0xAD, 0x5A, 0x83, 0x33,
            0x63, 0x02, 0xAA, 0x71, 0xC8, 0x19, 0x49, 0xD9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0,
            0xE9, 0x0F, 0xD5, 0x80, 0xBE, 0xCD, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE,
            0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xC3, 0xEC, 0xDB, 0xA1, 0x8D, 0x3D,
            0x97, 0x00, 0xCF, 0x2B, 0x76, 0x82, 0xD6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3, 0x30, 0xEF,
            0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xC0, 0xDE, 0x1C, 0xFD, 0x4D, 0x92, 0x75, 0x06, 0x8A,
            0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xD4, 0xA8, 0x96, 0xF9, 0xC5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4C,
            0x5E, 0x78, 0x38, 0x8C, 0xD1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9C, 0x1E, 0x43, 0xC7, 0xFC, 0x04,
            0x51, 0x99, 0x6D, 0x0D, 0xFA, 0xDF, 0x7E, 0x24, 0x3B, 0xAB, 0xCE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB,
            0x3C, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2C, 0xD3, 0xE7, 0x6E, 0xC4, 0x03, 0x56, 0x44, 0x7F, 0xA9,
            0x2A, 0xBB, 0xC1, 0x53, 0xDC, 0x0B, 0x9D, 0x6C, 0x31, 0x74, 0xF6, 0x46, 0xAC, 0x89, 0x14, 0xE1,
            0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xD0, 0xED, 0xCC, 0x42, 0x98, 0xA4, 0x28, 0x5C, 0xF8, 0x86,
        ]
        # fmt: on

        self.whirlpool_matrix = [
            [0x01, 0x09, 0x02, 0x05, 0x08, 0x01, 0x04, 0x01],
            [0x01, 0x01, 0x09, 0x02, 0x05, 0x08, 0x01, 0x04],
            [0x04, 0x01, 0x01, 0x09, 0x02, 0x05, 0x08, 0x01],
            [0x01, 0x04, 0x01, 0x01, 0x09, 0x02, 0x05, 0x08],
            [0x08, 0x01, 0x04, 0x01, 0x01, 0x09, 0x02, 0x05],
            [0x05, 0x08, 0x01, 0x04, 0x01, 0x01, 0x09, 0x02],
            [0x02, 0x05, 0x08, 0x01, 0x04, 0x01, 0x01, 0x09],
            [0x09, 0x02, 0x05, 0x08, 0x01, 0x04, 0x01, 0x01],
        ]

        self.whirlpool_matrix_description = [self.whirlpool_matrix, self.irreducible_polynomial, word_size]

        super().__init__(
            family_name="whirlpool_hash_function",
            cipher_type="hash_function",
            cipher_inputs=[INPUT_MESSAGE],
            cipher_inputs_bit_size=[self.cipher_block_size],
            cipher_output_bit_size=self.cipher_block_size,
        )

        self.add_round()

        round_key = self.add_constant_component(self.cipher_block_size, 0x00)  # Initial Key value

        add_round_key = self.add_XOR_component(
            [INPUT_MESSAGE, round_key.id],
            [list(range(self.cipher_block_size)), list(range(self.cipher_block_size))],
            self.cipher_block_size,
        )

        self.add_intermediate_output_component(
            [add_round_key.id], [list(range(self.cipher_block_size))], self.cipher_block_size, INTERMEDIATE_OUTPUT
        )

        add_round_constant = round_key
        for round_number in range(number_of_rounds):
            sboxes_components = self.create_sbox_component(add_round_key)
            shift_column_components = self.create_shift_column_components(sboxes_components, word_size)
            mix_row_components = self.create_mix_row_components(shift_column_components)

            round_constant = self.create_round_constant_component(round_number)
            key_sboxes_components = self.create_sbox_component(add_round_constant)
            key_shift_column_components = self.create_shift_column_components(key_sboxes_components, word_size)
            key_mix_row_components = self.create_mix_row_components(key_shift_column_components)

            add_round_constant = self.add_XOR_component(
                [key_mix_row_components[i].id for i in range(self.num_columns)] + [round_constant.id],
                [list(range(self.column_size)) for _ in range(self.num_columns)]
                + [list(range(self.cipher_block_size))],
                self.cipher_block_size,
            )

            add_round_key = self.add_XOR_component(
                [mix_row_components[i].id for i in range(self.num_columns)] + [add_round_constant.id],
                [list(range(self.column_size)) for _ in range(self.num_columns)]
                + [list(range(self.cipher_block_size))],
                self.cipher_block_size,
            )

            self.add_intermediate_output_component(
                [add_round_constant.id],
                [list(range(self.cipher_block_size))],
                self.cipher_block_size,
                INTERMEDIATE_OUTPUT,
            )
            if round_number != number_of_rounds - 1:
                self.add_round()

        output = self.add_XOR_component(
            [INPUT_MESSAGE, add_round_key.id],
            [list(range(self.cipher_block_size)), list(range(self.cipher_block_size))],
            self.cipher_block_size,
        )

        self.add_cipher_output_component([output.id], [list(range(self.cipher_block_size))], self.cipher_block_size)

    def create_sbox_component(self, add_round_key):
        sboxes_components = []
        for j in range(self.num_sboxes):
            sbox = self.add_SBOX_component(
                [add_round_key.id],
                [list(range(j * self.sbox_bit_size, (j + 1) * self.sbox_bit_size))],
                self.sbox_bit_size,
                self.sbox,
            )
            sboxes_components.append(sbox)

        return sboxes_components

    def create_shift_column_components(self, sboxes_components, word_size):
        shift_column_components = []
        for j in range(self.num_columns):
            rotation = self.add_rotate_component(
                [
                    sboxes_components[i].id
                    for i in range(j, j + self.num_columns * (self.num_columns - 1) + 1, self.num_columns)
                ],
                [list(range(self.sbox_bit_size)) for _ in range(self.num_columns)],
                self.column_size,
                word_size * j,
            )
            shift_column_components.append(rotation)

        return shift_column_components

    def create_mix_row_components(self, shift_column_components):
        mix_row_components = []
        for j in range(self.num_rows):
            mix_row = self.add_mix_column_component(
                [shift_column_components[i].id for i in range(self.num_rows)],
                [list(range(j * self.num_rows, (j + 1) * self.num_rows)) for _ in range(self.num_rows)],
                self.row_size,
                self.whirlpool_matrix_description,
            )
            mix_row_components.append(mix_row)

        return mix_row_components

    def create_round_constant_component(self, round_number):
        round_constant_value = (
            ["0x"] + [format(self.sbox[8 * (round_number) + j], "02x") for j in range(8)] + ["00" for _ in range(56)]
        )
        round_constant_string = "".join(round_constant_value)
        round_constant_hex_value = int(round_constant_string, 16)
        round_constant = self.add_constant_component(self.cipher_block_size, round_constant_hex_value)

        return round_constant
