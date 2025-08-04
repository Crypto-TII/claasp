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

import math
from itertools import chain

from claasp.cipher import Cipher
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT


PARAMETERS_CONFIGURATION_LIST = [{"key_length": 128, "number_of_rounds": 16}]


class TwofishBlockCipher(Cipher):
    """
    Construct an instance of the TwofishBlockCipher class.

    INPUT:

    - ``key_length`` -- **integer** (default: `128`); length of the cipher master key. Must be an integer between 1
      and 256 included
    - ``number_of_rounds`` -- **integer** (default: `16`); number of rounds of the cipher. Must be less or equal than 16

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.twofish_block_cipher import TwofishBlockCipher
        sage: cipher = TwofishBlockCipher()
        sage: cipher.print_cipher_structure_as_python_dictionary_to_file(  # doctest: +SKIP
        ....: "claasp/graph_representations/block_ciphers/twofish_key256_r16.py") # doctest: +SKIP

        sage: from claasp.ciphers.block_ciphers.twofish_block_cipher import TwofishBlockCipher
        sage: cipher = TwofishBlockCipher(key_length=256, number_of_rounds=16)
        sage: key = 0xD43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F
        sage: plaintext = 0x90AFE91BB288544F2C32DC239B2635E6
        sage: ciphertext = 0x6CB4561C40BF0A9705931CB6D408E7FA
        sage: cipher.evaluate([key, plaintext]) == ciphertext
        True
    """

    def __init__(self, key_length=128, number_of_rounds=16):
        if key_length not in range(257):
            raise ValueError("key_length incorrect (it should be in the set {0, 1, 2, ..., 256}).")
        if number_of_rounds > 16:
            raise ValueError("number_of_rounds incorrect (it should be less or equal than 16).")

        self.cipher_block_size = 128
        self.key_block_size = key_length
        self.key_padding_length = 128 - self.key_block_size
        if self.key_block_size > 64:
            self.key_padding_length = int(64 * (math.ceil(self.key_block_size / 64.0))) - self.key_block_size
        self.key_size = self.key_block_size + self.key_padding_length
        self.key_k = int(self.key_size / 64)
        self.key_RS_polynomial = 333
        self.state_MDS_polynomial = 361

        super().__init__(
            family_name="twofish_block_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.key_block_size, self.cipher_block_size],
            cipher_output_bit_size=self.cipher_block_size,
        )

        self.MDS = [
            [0x01, 0xEF, 0x5B, 0x5B],
            [0x5B, 0xEF, 0xEF, 0x01],
            [0xEF, 0x5B, 0x01, 0xEF],
            [0xEF, 0x01, 0xEF, 0x5B],
        ]

        self.RS = [
            [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
            [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
            [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
            [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
        ]

        # fmt: off
        self.q_PERMUTATIONS = {
            0: [
                0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
                0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
                0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
                0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
                0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
                0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
                0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
                0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
                0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
                0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
                0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
                0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
                0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
                0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
                0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
                0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
            ],
            1: [
                0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
                0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
                0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
                0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
                0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
                0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
                0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
                0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
                0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
                0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
                0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
                0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
                0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
                0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
                0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
                0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91,
            ]
        }
        # fmt: on
        # Rounds definition :
        # Round 0 different from others since it starts with input whitening
        self.add_round()

        if self.key_padding_length != 0:
            key_padding = self.add_constant_component(self.key_padding_length, 0)
            master_key = self.add_permutation_component(
                [key_padding.id, INPUT_KEY],
                [list(range(self.key_padding_length)), list(range(self.key_block_size))],
                self.key_size,
                list(range(self.key_block_size)),
            )
        else:
            master_key = self.add_permutation_component(
                [INPUT_KEY], [list(range(self.key_block_size))], self.key_block_size, list(range(self.key_block_size))
            )

        M_e = [master_key for _ in range(self.key_k)]
        M_e_positions = [list(range(64 * i, 64 * i + 32)) for i in range(self.key_k)]

        M_o = [master_key for _ in range(self.key_k)]
        M_o_positions = [list(range(64 * i + 32, 64 * i + 64)) for i in range(self.key_k)]

        S = [0] * self.key_k
        S_positions = [0] * self.key_k
        for i in range(self.key_k):
            m = self.add_mix_column_component(
                [master_key.id for _ in range(8)],
                [list(range(64 * i + 8 * j, 64 * i + 8 * (j + 1))) for j in range(8)],
                32,
                [self.RS, self.key_RS_polynomial, 8],
            )
            S[self.key_k - 1 - i] = m
            S_positions[self.key_k - 1 - i] = list(range(32))

        # Key Schedule
        keys_list = [0] * (2 * number_of_rounds + 8)
        for i in range(4):
            X1 = self.add_constant_component(32, 2 * i + 2 * i * 2**8 + 2 * i * 2**16 + 2 * i * 2**24)
            X2 = self.add_constant_component(
                32, (2 * i + 1) + (2 * i + 1) * 2**8 + (2 * i + 1) * 2**16 + (2 * i + 1) * 2**24
            )
            A = self.h_function(X1.id, [M_e[k].id for k in range(self.key_k)], M_e_positions)
            B = self.h_function(X2.id, [M_o[k].id for k in range(self.key_k)], M_o_positions)
            keys_list[2 * i] = self.add_MODADD_component(
                [A, B],
                [
                    list(chain(range(24, 32), range(16, 24), range(8, 16), range(8))),
                    list(chain(range(16, 24), range(8, 16), range(8), range(24, 32))),
                ],
                32,
            )
            B1 = self.add_SHIFT_component(
                [B], [list(chain(range(16, 24), range(8, 16), range(8), range(24, 32)))], 32, -1
            )
            A1 = self.add_MODADD_component(
                [A, B1.id], [list(chain(range(24, 32), range(16, 24), range(8, 16), range(8))), list(range(32))], 32
            )
            keys_list[2 * i + 1] = A1

        state = [0, 0, 0, 0]
        for i in range(2):
            s0 = self.add_XOR_component(
                [INPUT_PLAINTEXT, keys_list[2 * i].id],
                [
                    list(
                        chain(
                            range(32 * 2 * i + 24, 32 * 2 * i + 32),
                            range(32 * 2 * i + 16, 32 * 2 * i + 24),
                            range(32 * 2 * i + 8, 32 * 2 * i + 16),
                            range(32 * 2 * i, 32 * 2 * i + 8),
                        )
                    ),
                    list(range(32)),
                ],
                32,
            )
            state[2 * i] = s0
            s1 = self.add_XOR_component(
                [INPUT_PLAINTEXT, keys_list[2 * i + 1].id],
                [
                    list(
                        chain(
                            range(32 * (2 * i + 1) + 24, 32 * (2 * i + 1) + 32),
                            range(32 * (2 * i + 1) + 16, 32 * (2 * i + 1) + 24),
                            range(32 * (2 * i + 1) + 8, 32 * (2 * i + 1) + 16),
                            range(32 * (2 * i + 1), 32 * (2 * i + 1) + 8),
                        )
                    ),
                    list(chain(range(9, 32), range(9))),
                ],
                32,
            )
            state[2 * i + 1] = s1

        for round_number in range(number_of_rounds):
            # Key Schedule
            X1 = self.add_constant_component(
                32,
                (2 * round_number + 8)
                + (2 * round_number + 8) * 2**8
                + (2 * round_number + 8) * 2**16
                + (2 * round_number + 8) * 2**24,
            )
            X2 = self.add_constant_component(
                32,
                (2 * round_number + 9)
                + (2 * round_number + 9) * 2**8
                + (2 * round_number + 9) * 2**16
                + (2 * round_number + 9) * 2**24,
            )
            A = self.h_function(X1.id, [M_e[k].id for k in range(self.key_k)], M_e_positions)
            B = self.h_function(X2.id, [M_o[k].id for k in range(self.key_k)], M_o_positions)
            keys_list[(2 * round_number + 8)] = self.add_MODADD_component(
                [A, B],
                [
                    list(chain(range(24, 32), range(16, 24), range(8, 16), range(8))),
                    list(chain(range(16, 24), range(8, 16), range(8), range(24, 32))),
                ],
                32,
            )
            B1 = self.add_SHIFT_component(
                [B], [list(chain(range(16, 24), range(8, 16), range(8), range(24, 32)))], 32, -1
            )
            A1 = self.add_MODADD_component(
                [A, B1.id], [list(chain(range(24, 32), range(16, 24), range(8, 16), range(8))), list(range(32))], 32
            )
            keys_list[(2 * round_number + 9)] = A1

            # Round Function
            T0 = self.h_function(state[0].id, [S[k].id for k in range(self.key_k)], S_positions)
            X = self.add_rotate_component([state[1].id], [list(range(32))], 32, -8)
            T1 = self.h_function(X.id, [S[k].id for k in range(self.key_k)], S_positions)
            F0 = self.add_MODADD_component(
                [T0, T1, keys_list[2 * round_number + 8].id],
                [
                    list(chain(range(24, 32), range(16, 24), range(8, 16), range(8))),
                    list(chain(range(24, 32), range(16, 24), range(8, 16), range(8))),
                    list(range(32)),
                ],
                32,
            )
            FT = self.add_SHIFT_component(
                [T1], [list(chain(range(24, 32), range(16, 24), range(8, 16), range(8)))], 32, -1
            )
            F1 = self.add_MODADD_component(
                [T0, FT.id, keys_list[2 * round_number + 9].id],
                [
                    list(chain(range(24, 32), range(16, 24), range(8, 16), range(8))),
                    list(range(32)),
                    list(chain(range(9, 32), range(9))),
                ],
                32,
            )
            R0_to_rot = self.add_XOR_component([state[2].id, F0.id], [list(range(32)), list(range(32))], 32)
            R0 = self.add_rotate_component([R0_to_rot.id], [list(range(32))], 32, 1)
            R1 = self.add_XOR_component([state[3].id, F1.id], [list(range(1, 32)) + [0], list(range(32))], 32)
            state[2] = state[0]
            state[3] = state[1]
            state[0] = R0
            state[1] = R1

            # Round Output
            if round_number == number_of_rounds - 1:
                output = [0, 0, 0, 0]
                for i in range(2):
                    output[2 * i] = self.add_XOR_component(
                        [state[(2 * i + 2) % 4].id, keys_list[2 * i + 4].id], [list(range(32)) for _ in range(2)], 32
                    )
                    output[2 * i + 1] = self.add_XOR_component(
                        [state[((2 * i + 1) + 2) % 4].id, keys_list[(2 * i + 1) + 4].id],
                        [list(range(32)), list(chain(range(9, 32), range(9)))],
                        32,
                    )
                self.add_cipher_output_component(
                    [output[j].id for j in range(4)],
                    [list(chain(range(24, 32), range(16, 24), range(8, 16), range(8))) for _ in range(4)],
                    self.cipher_block_size,
                )
            else:
                self.add_intermediate_output_component(
                    [state[i].id for i in range(4)],
                    [list(range(32)) for _ in range(4)],
                    self.cipher_block_size,
                    "round_output",
                )
                self.add_round()

    def h_function(self, X, L, L_bits):
        y_i = [[0, 0, 0, 0] for _ in range(self.key_k + 1)]
        y2_j = X

        if self.key_k == 4:
            y4_j = X
            y_i[3] = [
                self.add_SBOX_component(
                    [y4_j], [list(range(8 * (3 - j), 8 * (4 - j)))], 8, self.q_PERMUTATIONS[int(abs(j - 1.5))]
                )
                for j in range(4)
            ]
            y3_j = self.add_XOR_component(
                [y_i[3][j].id for j in range(4)] + [L[3]], [list(range(8)) for _ in range(4)] + [L_bits[3]], 32
            )
            y_i[2] = [
                self.add_SBOX_component(
                    [y3_j.id], [list(range(8 * j, 8 * (j + 1)))], 8, self.q_PERMUTATIONS[1 - int(j / 2)]
                )
                for j in range(4)
            ]
            y2_j = self.add_XOR_component(
                [y_i[2][j].id for j in range(4)] + [L[2]], [list(range(8)) for _ in range(4)] + [L_bits[2]], 32
            )
            y_i[1] = [
                self.add_SBOX_component([y2_j.id], [list(range(8 * j, 8 * (j + 1)))], 8, self.q_PERMUTATIONS[j % 2])
                for j in range(4)
            ]
            y1_j = self.add_XOR_component(
                [y_i[1][j].id for j in range(4)] + [L[1]], [list(range(8)) for _ in range(4)] + [L_bits[1]], 32
            )

        elif self.key_k == 3:
            y3_j = X
            y_i[2] = [
                self.add_SBOX_component(
                    [y3_j], [list(range(8 * (3 - j), 8 * (4 - j)))], 8, self.q_PERMUTATIONS[1 - int(j / 2)]
                )
                for j in range(4)
            ]
            y2_j = self.add_XOR_component(
                [y_i[2][j].id for j in range(4)] + [L[2]], [list(range(8)) for _ in range(4)] + [L_bits[2]], 32
            )
            y_i[1] = [
                self.add_SBOX_component([y2_j.id], [list(range(8 * j, 8 * (j + 1)))], 8, self.q_PERMUTATIONS[j % 2])
                for j in range(4)
            ]
            y1_j = self.add_XOR_component(
                [y_i[1][j].id for j in range(4)] + [L[1]], [list(range(8)) for _ in range(4)] + [L_bits[1]], 32
            )

        elif self.key_k == 2:
            y_i[1] = [
                self.add_SBOX_component([y2_j], [list(range(8 * (3 - j), 8 * (4 - j)))], 8, self.q_PERMUTATIONS[j % 2])
                for j in range(4)
            ]
            y1_j = self.add_XOR_component(
                [y_i[1][j].id for j in range(4)] + [L[1]], [list(range(8)) for _ in range(4)] + [L_bits[1]], 32
            )

        y_i[0] = [
            self.add_SBOX_component([y1_j.id], [list(range(8 * j, 8 * (j + 1)))], 8, self.q_PERMUTATIONS[int(j / 2)])
            for j in range(4)
        ]
        y0_j = self.add_XOR_component(
            [y_i[0][j].id for j in range(4)] + [L[0]], [list(range(8)) for _ in range(4)] + [L_bits[0]], 32
        )

        y = [
            self.add_SBOX_component([y0_j.id], [list(range(8 * j, 8 * (j + 1)))], 8, self.q_PERMUTATIONS[1 - (j % 2)])
            for j in range(4)
        ]

        z = self.add_mix_column_component(
            [y[j].id for j in range(4)],
            [list(range(8)) for _ in range(4)],
            32,
            [self.MDS, self.state_MDS_polynomial, 8],
        )
        return z.id
