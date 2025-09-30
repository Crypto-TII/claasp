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


class SM4(Cipher):
    """
    Return a cipher object of SM4 Block Cipher.
    The technical specifications along with the test vectors can be found here: http://www.gmbz.org.cn/upload/2025-01-23/1737625646289030731.pdf

    EXAMPLES::

    sage: from claasp.ciphers.block_ciphers.sm4_block_cipher import SM4
    sage: sm4 = SM4()
    sage: key = 0x0123456789ABCDEFFEDCBA9876543210
    sage: plaintext = 0x0123456789ABCDEFFEDCBA9876543210
    sage: ciphertext = 0x681EDF34D206965E86B3E94F536E4246
    sage: sm4.evaluate([key, plaintext]) == ciphertext
    True
    """

    def __init__(self, number_of_rounds=32, word_size=8, state_size=8):
        # cipher dictionary initialize
        self.CIPHER_BLOCK_SIZE = 128
        self.KEY_BLOCK_SIZE = 128
        self.NROUNDS = number_of_rounds
        self.NUM_ROWS = state_size
        self.SBOX_BIT_SIZE = word_size
        self.ROW_SIZE = state_size * word_size
        self.round_keys = {}

        super().__init__(
            family_name="sm4_block_cipher",
            cipher_type="BLOCK_CIPHER",
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.KEY_BLOCK_SIZE, self.CIPHER_BLOCK_SIZE],
            cipher_output_bit_size=self.CIPHER_BLOCK_SIZE,
        )
        # fmt: off
        self.sbox = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
        ]
        self.FK = [
            0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
        ]

        self.CK = [
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
        ]
        # fmt: on

        word_bits = word_size * 4

        def encrypt_block(self, INPUT_PLAINTEXT, INPUT_KEY, word_bits):
            K = []
            for idx in range(4):
                FK_const = self.add_constant_component(word_bits, self.FK[idx])
                Ki = self.add_XOR_component(
                    [INPUT_KEY, FK_const.id],
                    [
                        [i for i in range(idx * 32, (idx + 1) * 32)],
                        [i for i in range(32)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                K.append(Ki)

            X = [
                {"id": INPUT_PLAINTEXT, "bit_position": list(range(32))},
                {"id": INPUT_PLAINTEXT, "bit_position": list(range(32, 64))},
                {"id": INPUT_PLAINTEXT, "bit_position": list(range(64, 96))},
                {"id": INPUT_PLAINTEXT, "bit_position": list(range(96, 128))},
            ]

            for i in range(self.NROUNDS):
                CK_const = self.add_constant_component(word_bits, self.CK[i])

                t1 = self.add_XOR_component(
                    [K[i + 3].id, CK_const.id],
                    [
                        [j for j in range(self.KEY_BLOCK_SIZE // 4)],
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                t2 = self.add_XOR_component(
                    [t1.id, K[i + 2].id],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        [j for j in range(self.KEY_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                temp_k = self.add_XOR_component(
                    [t2.id, K[i + 1].id],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        [j for j in range(self.KEY_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )

                sboxes_k = [
                    self.add_SBOX_component(
                        [temp_k.id], [[b * 8 + k for k in range(8)]], 8, self.sbox
                    )
                    for b in range(4)
                ]
                ids_k = [c.id for c in sboxes_k]
                pos_k = [list(range(8)) for _ in range(4)]

                rot13 = self.add_rotate_component(ids_k, pos_k, word_bits, -13)
                rot23 = self.add_rotate_component(ids_k, pos_k, word_bits, -23)
                xor_rot = self.add_XOR_component(
                    [rot13.id, rot23.id],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )

                L_prime = self.add_XOR_component(
                    [sboxes_k[b].id for b in range(4)] + [xor_rot.id],
                    [list(range(8)) for _ in range(4)] + [list(range(32))],
                    32,
                )

                Ki4 = self.add_XOR_component(
                    [L_prime.id, K[i].id],
                    [
                        [j for j in range(self.KEY_BLOCK_SIZE // 4)],
                        [j for j in range(self.KEY_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                K.append(Ki4)
                rk_i = Ki4

                t1 = self.add_XOR_component(
                    [X[i + 3]["id"], rk_i.id],
                    [
                        X[i + 3]["bit_position"],
                        [j for j in range(self.KEY_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                t2 = self.add_XOR_component(
                    [t1.id, X[i + 2]["id"]],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        X[i + 2]["bit_position"],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                temp_x = self.add_XOR_component(
                    [t2.id, X[i + 1]["id"]],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        X[i + 1]["bit_position"],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )

                sboxes_x = [
                    self.add_SBOX_component(
                        [temp_x.id], [[b * 8 + k for k in range(8)]], 8, self.sbox
                    )
                    for b in range(4)
                ]
                ids_x = [c.id for c in sboxes_x]
                pos_x = [list(range(8)) for _ in range(4)]

                rot2 = self.add_rotate_component(ids_x, pos_x, word_bits, -2)
                rot10 = self.add_rotate_component(ids_x, pos_x, word_bits, -10)
                rot18 = self.add_rotate_component(ids_x, pos_x, word_bits, -18)
                rot24 = self.add_rotate_component(ids_x, pos_x, word_bits, -24)

                xor_rot2_10 = self.add_XOR_component(
                    [rot2.id, rot10.id],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                xor_rot18_24 = self.add_XOR_component(
                    [rot18.id, rot24.id],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                xor_all = self.add_XOR_component(
                    [xor_rot2_10.id, xor_rot18_24.id],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )

                L_out = self.add_XOR_component(
                    [sboxes_x[b].id for b in range(4)] + [xor_all.id],
                    [list(range(8)) for _ in range(4)]
                    + [list(range(self.CIPHER_BLOCK_SIZE // 4))],
                    32,
                )

                Xi4 = self.add_XOR_component(
                    [L_out.id, X[i]["id"]],
                    [
                        [j for j in range(self.CIPHER_BLOCK_SIZE // 4)],
                        X[i]["bit_position"],
                    ],
                    self.CIPHER_BLOCK_SIZE // 4,
                )

                self.add_round_key_output_component(
                    [rk_i.id],
                    [list(range(self.CIPHER_BLOCK_SIZE // 4))],
                    self.CIPHER_BLOCK_SIZE // 4,
                )
                self.add_round_output_component(
                    [Xi4.id],
                    [list(range(self.CIPHER_BLOCK_SIZE // 4))],
                    self.CIPHER_BLOCK_SIZE // 4,
                )

                X.append(
                    {
                        "id": Xi4.id,
                        "bit_position": list(range(self.CIPHER_BLOCK_SIZE // 4)),
                    }
                )
                if i < self.NROUNDS - 1:
                    self.add_round()

            C0 = X[self.NROUNDS + 3]
            C1 = X[self.NROUNDS + 2]
            C2 = X[self.NROUNDS + 1]
            C3 = X[self.NROUNDS]
            return C0, C1, C2, C3

        self.add_round()
        C0, C1, C2, C3 = encrypt_block(self, INPUT_PLAINTEXT, INPUT_KEY, word_bits)
        self.add_cipher_output_component(
            [C0["id"], C1["id"], C2["id"], C3["id"]],
            [
                C0["bit_position"],
                C1["bit_position"],
                C2["bit_position"],
                C3["bit_position"],
            ],
            self.CIPHER_BLOCK_SIZE,
        )
