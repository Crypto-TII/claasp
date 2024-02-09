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
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 10}]


class AES128BlockCipher(Cipher):
    """
    Return a cipher object of AES Block Cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `10`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: aes = AESBlockCipher()
        sage: key = 0x2b7e151628aed2a6abf7158809cf4f3c
        sage: plaintext = 0x6bc1bee22e409f96e93d7e117393172a
        sage: ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
        sage: aes.evaluate([key, plaintext]) == ciphertext
        True
    """

    def __init__(self, number_of_rounds=10):
        super().__init__(family_name="aes_block_cipher",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[128, 128],
                         cipher_output_bit_size=128)

        self.NROUNDS = number_of_rounds
        self.CIPHER_BLOCK_SIZE = 128
        self.KEY_BLOCK_SIZE = 128
        self.SBOX_BIT_SIZE = 8
        self.NUM_SBOXES = int(self.KEY_BLOCK_SIZE / self.SBOX_BIT_SIZE)  # 16
        self.WORD_BIT_SIZE = 32
        self.NUM_ROWS = int(self.KEY_BLOCK_SIZE / self.WORD_BIT_SIZE)  # 4

        self.SBOX = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
        ]
        self.ROUND_CONSTANT = [
            "0x01000000", "0x02000000", "0x04000000", "0x08000000",
            "0x10000000", "0x20000000", "0x40000000", "0x80000000",
            "0x1B000000", "0x36000000", "0x36000000", "0x6C000000",
            "0xD8000000", "0xAB000000", "0x4D000000", "0x9A000000"
        ]
        self.MIX_COLUMN = [
            [[0x02, 0x03, 0x01, 0x01],  # mixcolum matrix
             [0x01, 0x02, 0x03, 0x01],
             [0x01, 0x01, 0x02, 0x03],
             [0x03, 0x01, 0x01, 0x02]],
            0x11b,  # irreducible polynomial
            self.SBOX_BIT_SIZE]

        # Link keyschedule first round to key values
        keyschedule_linear_layer_components = INPUT_KEY

        # Rounds
        for round_number in range(number_of_rounds):

            self.add_round()

            # Round 0 is different from others since it contains the initial whitening
            if round_number == 0:
                xor_with_round_key_component = self.add_XOR_component([INPUT_KEY, INPUT_PLAINTEXT],
                                                                      [[i for i in range(self.KEY_BLOCK_SIZE)],
                                                                       [i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                                                      int(self.CIPHER_BLOCK_SIZE))

            # Key schedule round
            keyschedule_sbox_layer_components = self.add_keyschedule_sbox_layer(keyschedule_linear_layer_components,
                                                                                round_number)
            keyschedule_linear_layer_components = self.add_keyschedule_linear_layer(keyschedule_sbox_layer_components,
                                                                                    keyschedule_linear_layer_components,
                                                                                    round_number)

            self.add_intermediate_output_component(
                [keyschedule_linear_layer_components[i].id for i in range(self.NUM_ROWS)],
                [[i for i in range(self.WORD_BIT_SIZE)] for _ in range(self.NUM_ROWS)],
                self.KEY_BLOCK_SIZE,
                "round_key_output")

            # Round
            sbox_layer_components = self.add_sbox_layer(xor_with_round_key_component)
            shift_row_layer_components = self.add_shift_row_layer(sbox_layer_components)
            mix_column_layer_components = self.add_mix_column_layer(round_number, shift_row_layer_components)
            xor_with_round_key_component = self.add_xor_with_round_key(mix_column_layer_components,
                                                                       keyschedule_linear_layer_components,
                                                                       shift_row_layer_components, round_number)

            self.add_round_output_component(xor_with_round_key_component, number_of_rounds, round_number)

    def add_keyschedule_sbox_layer(self, keyschedule_linear_layer_components, round_number):
        if round_number == 0:
            input_component_id = INPUT_KEY
            start_bit = 96
        else:
            input_component_id = keyschedule_linear_layer_components[3].id
            start_bit = 0

        keyschedule_sbox_layer_components = []
        for i in range(self.NUM_ROWS):
            sbox_component = self.add_SBOX_component(
                [input_component_id],
                [list(range(start_bit + i * self.SBOX_BIT_SIZE, start_bit + (i + 1) * self.SBOX_BIT_SIZE))],
                self.SBOX_BIT_SIZE,
                self.SBOX)

            keyschedule_sbox_layer_components.append(sbox_component)

        return keyschedule_sbox_layer_components

    def add_keyschedule_linear_layer(self, keyschedule_sbox_layer_components, keyschedule_linear_layer_components,
                                     round_number):

        # Rotate output of the four S-Boxes
        rotate_component = self.add_rotate_component(
            [keyschedule_sbox_layer_components[0].id,
             keyschedule_sbox_layer_components[1].id,
             keyschedule_sbox_layer_components[2].id,
             keyschedule_sbox_layer_components[3].id],
            # rotate_left([k_0, k_1, k_2, k_3]) by 8 bits i.e. to [k_1, k_2, k_3, k_0]
            [list(range(self.SBOX_BIT_SIZE)),
             list(range(self.SBOX_BIT_SIZE)),
             list(range(self.SBOX_BIT_SIZE)),
             list(range(self.SBOX_BIT_SIZE))],  # [[0-7], [0-7], [0-7], [0-7]]
            self.WORD_BIT_SIZE,
            -self.SBOX_BIT_SIZE)

        # XOR output of rotation with keyschedule round constants
        constant = self.add_constant_component(32, int(self.ROUND_CONSTANT[round_number], 16))
        xor_component = self.add_XOR_component(
            [rotate_component.id,
             constant.id],  # [rotate] + [constant]
            [list(range(self.WORD_BIT_SIZE)),
             list(range(self.WORD_BIT_SIZE))],  # [[0-31], [0-31]]
            self.WORD_BIT_SIZE)

        # Apply four consecutive XORs
        new_keyschedule_linear_layer_components = []
        for i in range(self.NUM_ROWS):
            if round_number == 0:
                xor_second_operand_id = INPUT_KEY
                start_bit = i * self.WORD_BIT_SIZE  # 0-31, 32-63, 64-95, 96-127
            else:
                xor_second_operand_id = keyschedule_linear_layer_components[i].id
                start_bit = 0

            xor_component = self.add_XOR_component(
                [xor_component.id, xor_second_operand_id],
                [list(range(self.WORD_BIT_SIZE)),  # 0-31
                 list(range(start_bit, start_bit + self.WORD_BIT_SIZE))],  # 0-31 or 0-31, 32-63, 64-95, 96-127
                self.WORD_BIT_SIZE)

            new_keyschedule_linear_layer_components.append(xor_component)

        return new_keyschedule_linear_layer_components

    def add_sbox_layer(self, add_round_key):
        sbox_layer_components = []
        for j in range(self.NUM_SBOXES):
            sbox_component = self.add_SBOX_component(
                [add_round_key.id],
                [[i for i in range(j * self.SBOX_BIT_SIZE, (j + 1) * self.SBOX_BIT_SIZE)]],
                self.SBOX_BIT_SIZE, self.SBOX)
            sbox_layer_components.append(sbox_component)

        return sbox_layer_components

    def add_shift_row_layer(self, sbox_layer_components):
        shift_row_layer_components = []
        for j in range(self.NUM_ROWS):
            rotation_component = self.add_rotate_component(
                [sbox_layer_components[i].id for i in
                 range(j, j + self.NUM_ROWS * (self.NUM_ROWS - 1) + 1, self.NUM_ROWS)],
                [[i for i in range(self.SBOX_BIT_SIZE)] for _ in range(self.NUM_ROWS)],
                self.WORD_BIT_SIZE,
                -self.SBOX_BIT_SIZE * j)
            shift_row_layer_components.append(rotation_component)

        return shift_row_layer_components

    def add_mix_column_layer(self, round_number, shift_row_layer_components):
        mix_column_layer_components = []
        if round_number != self.NROUNDS - 1:
            for j in range(self.NUM_ROWS):
                mix_column_component = self.add_mix_column_component(
                    [shift_row_layer_components[i].id for i in range(self.NUM_ROWS)],
                    [[i for i in range(j * self.SBOX_BIT_SIZE, (j + 1) * self.SBOX_BIT_SIZE)] for _ in
                     range(self.NUM_ROWS)],
                    self.WORD_BIT_SIZE,
                    self.MIX_COLUMN)
                mix_column_layer_components.append(mix_column_component)

        return mix_column_layer_components

    def add_xor_with_round_key(self, mix_column_layer_components, keyschedule_linear_layer_components,
                               shift_row_layer_components, round_number):
        # if not last round, XOR round key with mix column output
        if round_number != self.NROUNDS - 1:
            xor_component = self.add_XOR_component(
                [mix_column_layer_components[i].id for i in range(self.NUM_ROWS)] +
                [keyschedule_linear_layer_components[i].id for i in range(self.NUM_ROWS)],
                [[i for i in range(self.WORD_BIT_SIZE)] for _ in range(2 * self.NUM_ROWS)],
                self.CIPHER_BLOCK_SIZE)
        # if last round, XOR round key with shift row output
        else:
            shift_rows_ids = []
            for i in range(self.NUM_ROWS):
                shift_rows_ids.extend([shift_row_layer_components[j].id for j in range(self.NUM_ROWS)])
            shift_rows_input_position_lists = []
            for i in range(self.NUM_ROWS):
                shift_rows_input_position_lists.extend(
                    [[j for j in range(i * self.SBOX_BIT_SIZE, (i + 1) * self.SBOX_BIT_SIZE)] for _ in
                     range(self.NUM_ROWS)])

            xor_component = self.add_XOR_component(
                shift_rows_ids +
                [keyschedule_linear_layer_components[i].id for i in range(self.NUM_ROWS)],
                shift_rows_input_position_lists + [[i for i in range(self.WORD_BIT_SIZE)] for _ in
                                                   range(self.NUM_ROWS)],
                self.CIPHER_BLOCK_SIZE)

        return xor_component

    def add_round_output_component(self, add_round_key, number_of_rounds, round_number):
        if round_number == number_of_rounds - 1:
            self.add_cipher_output_component([add_round_key.id],
                                             [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                             self.CIPHER_BLOCK_SIZE)
        else:
            self.add_intermediate_output_component([add_round_key.id],
                                                   [[i for i in range(self.CIPHER_BLOCK_SIZE)]],
                                                   self.CIPHER_BLOCK_SIZE,
                                                   "round_output")
