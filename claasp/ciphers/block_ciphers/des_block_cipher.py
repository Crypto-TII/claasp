
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

PARAMETERS_CONFIGURATION_LIST = [{'number_of_sboxes': 8, 'number_of_rounds': 16}]


class DESBlockCipher(Cipher):
    """
    Return a cipher object of DES Block Cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `16`); number of rounds of the cipher.
      Must be less or equal than 16
    - ``number_of_sboxes`` -- **integer** (default: `8`); number of SBoxes considered. Must be equal to 2, 4, 6 or 8

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
        sage: des = DESBlockCipher()
        sage: key = 0x133457799BBCDFF1
        sage: plaintext = 0x0123456789ABCDEF
        sage: ciphertext = 0x85E813540F0AB405
        sage: des.evaluate([key, plaintext]) == ciphertext
        True
    """

    def __init__(self, number_of_rounds=16, number_of_sboxes=8):

        if number_of_sboxes not in (2, 4, 6, 8):
            raise ValueError("number_of_sboxes incorrect (it should be in the set {2, 4, 6, 8}).")
        if number_of_rounds > 16:
            raise ValueError("number_of_rounds incorrect (it should be less or equal than 16).")

        self.CIPHER_BLOCK_SIZE = number_of_sboxes * 4 * 2
        self.KEY_BLOCK_SIZE = self.CIPHER_BLOCK_SIZE
        self.HALF_ROUND_KEY_SIZE = int(number_of_sboxes / 2) * 7
        self.SBOX_BIT_SIZE = 6

        super().__init__(family_name="des_block_cipher",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[self.KEY_BLOCK_SIZE, self.CIPHER_BLOCK_SIZE],
                         cipher_output_bit_size=self.CIPHER_BLOCK_SIZE)

        # As many as number_of_sboxes
        self.SBOX = {
            1: [
                0xE, 0x0, 0x4, 0xF, 0xD, 0x7, 0x1, 0x4,
                0x2, 0xE, 0xF, 0x2, 0xB, 0xD, 0x8, 0x1,
                0x3, 0xA, 0xA, 0x6, 0x6, 0xC, 0xC, 0xB,
                0x5, 0x9, 0x9, 0x5, 0x0, 0x3, 0x7, 0x8,
                0x4, 0xF, 0x1, 0xC, 0xE, 0x8, 0x8, 0x2,
                0xD, 0x4, 0x6, 0x9, 0x2, 0x1, 0xB, 0x7,
                0xF, 0x5, 0xC, 0xB, 0x9, 0x3, 0x7, 0xE,
                0x3, 0xA, 0xA, 0x0, 0x5, 0x6, 0x0, 0xD,
            ],
            2: [
                0xF, 0x3, 0x1, 0xD, 0x8, 0x4, 0xE, 0x7,
                0x6, 0xF, 0xB, 0x2, 0x3, 0x8, 0x4, 0xE,
                0x9, 0xC, 0x7, 0x0, 0x2, 0x1, 0xD, 0xA,
                0xC, 0x6, 0x0, 0x9, 0x5, 0xB, 0xA, 0x5,
                0x0, 0xD, 0xE, 0x8, 0x7, 0xA, 0xB, 0x1,
                0xA, 0x3, 0x4, 0xF, 0xD, 0x4, 0x1, 0x2,
                0x5, 0xB, 0x8, 0x6, 0xC, 0x7, 0x6, 0xC,
                0x9, 0x0, 0x3, 0x5, 0x2, 0xE, 0xF, 0x9,
            ],
            3: [
                0xA, 0xD, 0x0, 0x7, 0x9, 0x0, 0xE, 0x9,
                0x6, 0x3, 0x3, 0x4, 0xF, 0x6, 0x5, 0xA,
                0x1, 0x2, 0xD, 0x8, 0xC, 0x5, 0x7, 0xE,
                0xB, 0xC, 0x4, 0xB, 0x2, 0xF, 0x8, 0x1,
                0xD, 0x1, 0x6, 0xA, 0x4, 0xD, 0x9, 0x0,
                0x8, 0x6, 0xF, 0x9, 0x3, 0x8, 0x0, 0x7,
                0xB, 0x4, 0x1, 0xF, 0x2, 0xE, 0xC, 0x3,
                0x5, 0xB, 0xA, 0x5, 0xE, 0x2, 0x7, 0xC,
            ],
            4: [
                0x7, 0xD, 0xD, 0x8, 0xE, 0xB, 0x3, 0x5,
                0x0, 0x6, 0x6, 0xF, 0x9, 0x0, 0xA, 0x3,
                0x1, 0x4, 0x2, 0x7, 0x8, 0x2, 0x5, 0xC,
                0xB, 0x1, 0xC, 0xA, 0x4, 0xE, 0xF, 0x9,
                0xA, 0x3, 0x6, 0xF, 0x9, 0x0, 0x0, 0x6,
                0xC, 0xA, 0xB, 0x1, 0x7, 0xD, 0xD, 0x8,
                0xF, 0x9, 0x1, 0x4, 0x3, 0x5, 0xE, 0xB,
                0x5, 0xC, 0x2, 0x7, 0x8, 0x2, 0x4, 0xE,
            ],
            5: [
                0x2, 0xE, 0xC, 0xB, 0x4, 0x2, 0x1, 0xC,
                0x7, 0x4, 0xA, 0x7, 0xB, 0xD, 0x6, 0x1,
                0x8, 0x5, 0x5, 0x0, 0x3, 0xF, 0xF, 0xA,
                0xD, 0x3, 0x0, 0x9, 0xE, 0x8, 0x9, 0x6,
                0x4, 0xB, 0x2, 0x8, 0x1, 0xC, 0xB, 0x7,
                0xA, 0x1, 0xD, 0xE, 0x7, 0x2, 0x8, 0xD,
                0xF, 0x6, 0x9, 0xF, 0xC, 0x0, 0x5, 0x9,
                0x6, 0xA, 0x3, 0x4, 0x0, 0x5, 0xE, 0x3,
            ],
            6: [
                0xC, 0xA, 0x1, 0xF, 0xA, 0x4, 0xF, 0x2,
                0x9, 0x7, 0x2, 0xC, 0x6, 0x9, 0x8, 0x5,
                0x0, 0x6, 0xD, 0x1, 0x3, 0xD, 0x4, 0xE,
                0xE, 0x0, 0x7, 0xB, 0x5, 0x3, 0xB, 0x8,
                0x9, 0x4, 0xE, 0x3, 0xF, 0x2, 0x5, 0xC,
                0x2, 0x9, 0x8, 0x5, 0xC, 0xF, 0x3, 0xA,
                0x7, 0xB, 0x0, 0xE, 0x4, 0x1, 0xA, 0x7,
                0x1, 0x6, 0xD, 0x0, 0xB, 0x8, 0x6, 0xD,
            ],
            7: [
                0x4, 0xD, 0xB, 0x0, 0x2, 0xB, 0xE, 0x7,
                0xF, 0x4, 0x0, 0x9, 0x8, 0x1, 0xD, 0xA,
                0x3, 0xE, 0xC, 0x3, 0x9, 0x5, 0x7, 0xC,
                0x5, 0x2, 0xA, 0xF, 0x6, 0x8, 0x1, 0x6,
                0x1, 0x6, 0x4, 0xB, 0xB, 0xD, 0xD, 0x8,
                0xC, 0x1, 0x3, 0x4, 0x7, 0xA, 0xE, 0x7,
                0xA, 0x9, 0xF, 0x5, 0x6, 0x0, 0x8, 0xF,
                0x0, 0xE, 0x5, 0x2, 0x9, 0x3, 0x2, 0xC,
            ],
            8: [
                0xD, 0x1, 0x2, 0xF, 0x8, 0xD, 0x4, 0x8,
                0x6, 0xA, 0xF, 0x3, 0xB, 0x7, 0x1, 0x4,
                0xA, 0xC, 0x9, 0x5, 0x3, 0x6, 0xE, 0xB,
                0x5, 0x0, 0x0, 0xE, 0xC, 0x9, 0x7, 0x2,
                0x7, 0x2, 0xB, 0x1, 0x4, 0xE, 0x1, 0x7,
                0x9, 0x4, 0xC, 0xA, 0xE, 0x8, 0x2, 0xD,
                0x0, 0xF, 0x6, 0xC, 0xA, 0x9, 0xD, 0x0,
                0xF, 0x3, 0x3, 0x5, 0x5, 0x6, 0x8, 0xB,
            ],
        }

        # In function of number_of_sboxes
        self.INITIAL_PERMUTATION = {
            2: [
                9, 1, 11, 3,
                13, 5, 15, 7,
                8, 0, 10, 2,
                12, 4, 14, 6,
            ],
            4: [
                25, 17, 9, 1, 27, 19, 11, 3,
                29, 21, 13, 5, 31, 23, 15, 7,
                24, 16, 8, 0, 26, 18, 10, 2,
                28, 20, 12, 4, 30, 22, 14, 6,
            ],
            6: [
                41, 33, 25, 17, 9, 1, 43, 35, 27, 19, 11, 3,
                45, 37, 29, 21, 13, 5, 47, 39, 31, 23, 15, 7,
                40, 32, 24, 16, 8, 0, 42, 34, 26, 18, 10, 2,
                44, 36, 28, 20, 12, 4, 46, 38, 30, 22, 14, 6,
            ],
            8: [
                57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
                56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
            ],
        }

        # In function of number_of_sboxes
        self.ROUND_PERMUTATION = {
            2: [
                1, 5, 0, 7,
                2, 3, 6, 4,
            ],
            4: [
                8, 12, 1, 15, 5, 9, 0, 7,
                13, 2, 3, 10, 11, 6, 4, 14,
            ],
            6: [
                8, 16, 22, 12, 1, 17, 23, 15, 5, 19, 9, 0,
                7, 13, 2, 3, 10, 18, 11, 21, 6, 4, 14, 20,
            ],
            8: [
                8, 16, 22, 30, 12, 27, 1, 17, 23, 15, 29, 5, 25, 19, 9, 0,
                7, 13, 24, 2, 3, 28, 10, 18, 31, 11, 21, 6, 4, 26, 14, 20,
            ],
        }

        # In function of number_of_sboxes
        self.KEY_PERMUTATION = {
            2: [
                7, 0, 8,
                1, 9, 2, 10,
                13, 6, 12,
                5, 11, 4, 3,
            ],
            4: [
                21, 14, 7, 0, 22, 15, 8,
                1, 23, 16, 9, 2, 24, 17,
                27, 20, 13, 6, 26, 19, 12,
                5, 25, 18, 11, 4, 10, 3,
            ],
            6: [
                35, 28, 21, 14, 7, 0, 36, 29, 22, 15,
                8, 1, 37, 30, 23, 16, 9, 2, 38, 31, 24,
                41, 34, 27, 20, 13, 6, 40, 33, 26, 19,
                12, 5, 39, 32, 25, 18, 11, 4, 17, 10, 3,
            ],
            8: [
                56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
                9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
                62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
                13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3,
            ],
        }

        # In function of number_of_sboxes
        self.EXPANSION_PERMUTATION = {
            2: [
                7, 0, 8,
                1, 9, 2, 10,
                13, 6, 12,
                5, 11, 4, 3,
            ],
            4: [
                21, 14, 7, 0, 22, 15, 8,
                1, 23, 16, 9, 2, 24, 17,
                27, 20, 13, 6, 26, 19, 12,
                5, 25, 18, 11, 4, 10, 3,
            ],
            6: [
                35, 28, 21, 14, 7, 0, 36, 29, 22, 15,
                8, 1, 37, 30, 23, 16, 9, 2, 38, 31, 24,
                41, 34, 27, 20, 13, 6, 40, 33, 26, 19,
                12, 5, 39, 32, 25, 18, 11, 4, 17, 10, 3,
            ],
            8: [
                31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8,
                7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
                15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
                23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
            ],
        }

        # In function of number_of_sboxes
        self.KEY_SUBSET = {
            2: [
                0, 4, 2,
                3, 6, 1,
                9, 8, 11,
                12, 7, 10,
            ],
            4: [
                13, 10, 0, 4, 2, 5,
                11, 3, 7, 6, 12, 1,
                26, 16, 22, 15, 25, 18,
                24, 19, 27, 21, 14, 17,
            ],
            6: [
                13, 16, 10, 0, 4, 2, 14, 5, 20, 9,
                18, 11, 3, 7, 15, 6, 19, 12, 1,
                33, 23, 29, 39, 22, 32, 37, 25, 40,
                36, 41, 31, 26, 38, 34, 28, 21, 24,
            ],
            8: [
                13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
                22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
                40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
                43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
            ],
        }

        # In function of number_of_sboxes
        self.FINAL_PERMUTATION = {
            2: [
                9, 1, 11, 3,
                13, 5, 15, 7,
                8, 0, 10, 2,
                12, 4, 14, 6,
            ],
            4: [
                19, 3, 23, 7, 27, 11, 31, 15,
                18, 2, 22, 6, 26, 10, 30, 14,
                17, 1, 21, 5, 25, 9, 29, 13,
                16, 0, 20, 4, 24, 8, 28, 12,
            ],
            6: [
                29, 5, 35, 11, 41, 17, 47, 23, 28, 4, 34, 10,
                40, 16, 46, 22, 27, 3, 33, 9, 39, 15, 45, 21,
                26, 2, 32, 8, 38, 14, 44, 20, 25, 1, 31, 7,
                37, 13, 43, 19, 24, 0, 30, 6, 36, 12, 42, 18,
            ],
            8: [
                57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
                56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
            ],
        }

        # Rounds definition:
        # Round 0 different from others since it starts with FirstAddRoundKey
        self.add_round()

        # state = self.add_permutation_component([INPUT_PLAINTEXT],
        #                                        [self.INITIAL_PERMUTATION[number_of_sboxes]],
        #                                        self.CIPHER_BLOCK_SIZE,
        #                                        list(range(self.CIPHER_BLOCK_SIZE)))
        # For the key recovery using linear crypta (Matsui), we ignore INITIAL_PERMUTATION.
        state = self.add_permutation_component([INPUT_PLAINTEXT],
                                               [list(range(number_of_sboxes * 8))],
                                               number_of_sboxes * 8,
                                               list(range(number_of_sboxes * 8)))

        key_state = self.add_permutation_component([INPUT_KEY],
                                                   [list(range(number_of_sboxes * 8))],
                                                   number_of_sboxes * 8,
                                                   list(range(number_of_sboxes * 8)))

        for round_number in range(number_of_rounds):
            # Key Schedule
            # KeyPerm
            if round_number == 0:
                left_key = self.add_permutation_component(
                    [key_state.id],
                    [self.KEY_PERMUTATION[number_of_sboxes][:self.HALF_ROUND_KEY_SIZE]],
                    self.HALF_ROUND_KEY_SIZE,
                    list(range(self.HALF_ROUND_KEY_SIZE)))
                right_key = self.add_permutation_component(
                    [key_state.id],
                    [self.KEY_PERMUTATION[number_of_sboxes][self.HALF_ROUND_KEY_SIZE:]],
                    self.HALF_ROUND_KEY_SIZE,
                    list(range(self.HALF_ROUND_KEY_SIZE)))
            else:
                left_key = left_round_key
                right_key = right_round_key

            if round_number in (0, 1, 8, 15):
                left_round_key = self.add_rotate_component([left_key.id],
                                                           [list(range(self.HALF_ROUND_KEY_SIZE))],
                                                           self.HALF_ROUND_KEY_SIZE,
                                                           -1)
                right_round_key = self.add_rotate_component([right_key.id],
                                                            [list(range(self.HALF_ROUND_KEY_SIZE))],
                                                            self.HALF_ROUND_KEY_SIZE,
                                                            -1)
            else:
                left_round_key = self.add_rotate_component([left_key.id],
                                                           [list(range(self.HALF_ROUND_KEY_SIZE))],
                                                           self.HALF_ROUND_KEY_SIZE,
                                                           -2)
                right_round_key = self.add_rotate_component([right_key.id],
                                                            [list(range(self.HALF_ROUND_KEY_SIZE))],
                                                            self.HALF_ROUND_KEY_SIZE,
                                                            -2)

            # KeyOutput
            round_key = self.add_permutation_component(
                [left_round_key.id, right_round_key.id],
                [self.KEY_SUBSET[number_of_sboxes][:number_of_sboxes * 3],
                 [self.KEY_SUBSET[number_of_sboxes][i] - self.HALF_ROUND_KEY_SIZE for i in
                  range(number_of_sboxes * 3, number_of_sboxes * 6)]],
                number_of_sboxes * 6,
                list(range(number_of_sboxes * 6)))

            # AddRoundKey to Expanded State
            keyed_state = self.add_XOR_component(
                [state.id, round_key.id],
                [[self.EXPANSION_PERMUTATION[number_of_sboxes][i] + number_of_sboxes * 4 for i in
                  range(number_of_sboxes * 6)], list(range(number_of_sboxes * 6))],
                number_of_sboxes * 6)

            # Sbox
            sbox_state = []
            for i in range(number_of_sboxes):
                sbox_output = self.add_SBOX_component([keyed_state.id],
                                                      [list(range(6 * i, 6 * i + 6))],
                                                      4,
                                                      self.SBOX[i + 1])
                sbox_state.append(sbox_output)

            # Sbox Permutation
            right_state_to_xor = self.add_permutation_component([sbox_state[i].id for i in range(number_of_sboxes)],
                                                                [list(range(4)) for _ in range(number_of_sboxes)],
                                                                number_of_sboxes * 4,
                                                                self.ROUND_PERMUTATION[number_of_sboxes])

            # XOR with Left Half
            right_state = self.add_XOR_component([state.id, right_state_to_xor.id],
                                                 [list(range(number_of_sboxes * 4)), list(range(number_of_sboxes * 4))],
                                                 number_of_sboxes * 4)

            # Round Output
            if round_number == number_of_rounds - 1:
                # state = self.add_permutation_component(
                #     [right_state.id, state.id],
                #     [list(range(number_of_sboxes * 4)), list(range(number_of_sboxes * 4, number_of_sboxes * 8))],
                #     self.CIPHER_BLOCK_SIZE,
                #     self.FINAL_PERMUTATION[number_of_sboxes])
                # self.add_cipher_output_component([state.id],
                #                                  [list(range(self.CIPHER_BLOCK_SIZE))],
                #                                  self.CIPHER_BLOCK_SIZE)
                # For the key recovery using linear crypta (Matsui), we ignore FINAL_PERMUTATION
                self.add_cipher_output_component([right_state.id, state.id],
                                                 [list(range(number_of_sboxes * 4)), list(range(number_of_sboxes * 4, number_of_sboxes * 8))],
                                                 self.CIPHER_BLOCK_SIZE)
                # self.add_cipher_output_component([state.id, right_state.id],
                #                                  [list(range(number_of_sboxes * 4, number_of_sboxes * 8)), list(range(number_of_sboxes * 4))],
                #                                  self.CIPHER_BLOCK_SIZE)
            else:
                state = self.add_permutation_component(
                    [state.id, right_state.id],
                    [list(range(number_of_sboxes * 4, number_of_sboxes * 8)), list(range(number_of_sboxes * 4))],
                    self.CIPHER_BLOCK_SIZE,
                    list(range(self.CIPHER_BLOCK_SIZE)))
                self.add_intermediate_output_component([state.id],
                                                       [list(range(self.CIPHER_BLOCK_SIZE))],
                                                       self.CIPHER_BLOCK_SIZE,
                                                       "round_output")
                self.add_round()
