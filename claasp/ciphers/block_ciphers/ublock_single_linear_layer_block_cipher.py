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

import numpy as np
import sys

from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY


PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 16},
    {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 24},
    {"block_bit_size": 256, "key_bit_size": 256, "number_of_rounds": 24},
]

SBOX = [0x7, 0x4, 0x9, 0xC, 0xB, 0xA, 0xD, 0x8, 0xF, 0xE, 0x1, 0x6, 0x0, 0x3, 0x2, 0x5]
SBOX_TK = [0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD]
SBOX_SIZE = 4
PL = [[1, 3, 4, 6, 0, 2, 7, 5], [2, 7, 8, 13, 3, 6, 9, 12, 1, 4, 15, 10, 14, 11, 5, 0]]
PR = [[2, 7, 5, 0, 1, 6, 4, 3], [6, 11, 1, 12, 9, 4, 2, 15, 7, 0, 13, 10, 14, 3, 8, 5]]
P_WORD_SIZE = 8
RC_SIZE = 32
ROTATE_SIZE = 32
# fmt: off
PK = [
    [6, 0, 8, 13, 1, 15, 5, 10, 4, 9, 12, 2, 11, 3, 7, 14],
    [
        10, 5, 15, 0, 2, 7, 8, 13, 14, 6, 4, 12, 1, 3, 11, 9, 24,
        25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23
    ],
    [
        10, 5, 15, 0, 2, 7, 8, 13, 1, 14, 4, 12, 9, 11, 3, 6, 24,
        25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23
    ],
]
PK_WORD_SIZE = 4
RC = [
    0x988cc9dd, 0xf0e4a1b5, 0x21357064, 0x8397d2c6, 0xc7d39682, 0x4f5b1e0a, 0x5e4a0f1b, 0x7c682d39,
    0x392d687c, 0xb3a7e2f6, 0xa7b3f6e2, 0x8e9adfcb, 0xdcc88d99, 0x786c293d, 0x30246175, 0xa1b5f0e4,
    0x8296d3c7, 0xc5d19480, 0x4a5e1b0f, 0x55410410, 0x6b7f3a2e, 0x17034652, 0xeffbbeaa, 0x1f0b4e5a,
]
# fmt: on


def generate_ublock_matrix(n, shift0, shift1, shift2):
    matrix = [[i] for i in range(n)]
    BITWISE_PERMUTATION = []
    for i in PL[0]:
        BITWISE_PERMUTATION.extend(list(range(i * (n // 16), i * (n // 16) + (n // 16))))
    for i in PR[0]:
        BITWISE_PERMUTATION.extend(list(range(i * (n // 16) + n // 2, i * (n // 16) + n // 2 + (n // 16))))

    for i in range(0, n // 2):
        matrix[i + n // 2].extend(matrix[i].copy())

    vector = matrix[n // 2 : (n - n // 4)][shift0:] + matrix[n // 2 : n - n // 4][:shift0]
    vector += matrix[n - n // 4 : n][shift0:] + matrix[n - n // 4 : n][:shift0]
    for i in range(0, n // 2):
        matrix[i].extend(vector[i])

    vector1 = matrix[0 : n // 4][shift1:] + matrix[0 : n // 4][:shift1]
    vector1 += matrix[n // 4 : n // 2][shift1:] + matrix[n // 4 : n // 2][:shift1]
    for i in range(n // 2, n):
        matrix[i].extend(vector1[i - n // 2])

    vector2 = matrix[n // 2 : n - n // 4][shift1:] + matrix[n // 2 : n - n // 4][:shift1]
    vector2 += matrix[n - n // 4:n][shift1:] + matrix[n - n // 4:n][:shift1]
    for i in range(0, n // 2):
        matrix[i].extend(vector2[i])

    vector3 = matrix[0 : n // 4][shift2:] + matrix[0 : n // 4][:shift2]
    vector3 += matrix[n // 4 : n // 2][shift2:] + matrix[n // 4 : n // 2][:shift2]
    for i in range(n // 2, n):
        matrix[i].extend(vector3[i - n // 2])

    for i in range(0, n // 2):
        matrix[i].extend(matrix[n // 2 + i].copy())

    matrix_reduced = []
    for equation in matrix:
        new_equation = []
        for element in set(equation):
            if equation.count(element) % 2 != 0:
                new_equation.append(element)
        matrix_reduced.append(new_equation)

    matrix_permuted = []
    for i in BITWISE_PERMUTATION:
        matrix_permuted.append(matrix_reduced[i])

    matrix = [[0] * n for _ in range(n)]
    for i, equation in enumerate(matrix_permuted):
        for element in equation:
            matrix[i][element] = 1

    linear_layer_matrix = np.array(matrix).T.tolist()

    return linear_layer_matrix


class UblockSingleLinearLayerBlockCipher(Cipher):
    """
    Construct an instance of the UblockBlockCipher class.
    Reference: http://www.jcr.cacrnet.org.cn/EN/10.13868/j.cnki.jcr.000334

    Following are some testing vectors:
    1. Ublock 128/128
    plaintext = 0x0123456789abcdeffedcba9876543210
    key = 0x0123456789abcdeffedcba9876543210
    ciphertext = 0x32122bedd023c429023470e1158c147d

    2. Ublock 128/256
    plaintext = 0x0123456789abcdeffedcba9876543210
    key = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
    ciphertext = 0x64accd6e34cac84d384cd4ba7aeadd19

    3. Ublock 256/256
    plaintext = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
    key = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
    ciphertext = 0xd8e9351c5f4d27ea842135ca1640ad4b0ce119bc25c03e7c329ea8fe93e7bdfe

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher round_key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `16`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when r is 0

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
        sage: ublock = UblockBlockCipher()
        sage: ublock.number_of_rounds
        16

        sage: ublock.component_from(0, 0).id
        'xor_0_0'

        sage: plaintext = 0x0123456789abcdeffedcba9876543210
        sage: key = 0x0123456789abcdeffedcba9876543210
        sage: ciphertext = 0x32122bedd023c429023470e1158c147d
        sage: ublock.evaluate([plaintext, key]) == ciphertext
        True
    """

    def __init__(self, block_bit_size=128, key_bit_size=128, number_of_rounds=16):
        self.half_block_bit_size = block_bit_size // 2
        self.key_block_size = key_bit_size // 4
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size

        self.check_parameters()

        super().__init__(
            family_name="ublock",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        state_left, state_right, key_0, key_1, key_2, key_3, round_key = self.round_initialization()

        for round_number in range(number_of_rounds):
            self.add_round()

            # encryption
            state_left, state_right = self.round_function(state_left, state_right, round_key)
            # round output
            self.add_round_key_output_component(round_key.id, round_key.input_bit_positions, self.block_bit_size)
            if round_number < number_of_rounds - 1:
                self.add_round_output_component(
                    state_left.id + state_right.id,
                    state_left.input_bit_positions + state_right.input_bit_positions,
                    self.block_bit_size,
                )
            # round_key schedule
            key_0, key_1, key_2, key_3, round_key = self.key_schedule(key_0, key_1, key_2, key_3, RC[round_number])

        # cipher output and round key output
        self.add_XOR_component(
            state_left.id + state_right.id + round_key.id,
            state_left.input_bit_positions + state_right.input_bit_positions + round_key.input_bit_positions,
            self.block_bit_size,
        )
        cipher_output = ComponentState([self.get_current_component_id()], [list(range(self.block_bit_size))])
        self.add_round_key_output_component(round_key.id, round_key.input_bit_positions, self.block_bit_size)
        self.add_cipher_output_component(cipher_output.id, cipher_output.input_bit_positions, self.block_bit_size)

    def check_parameters(self):
        if self.block_bit_size == 128:
            self.pl = PL[0]
            self.pr = PR[0]
            if self.key_bit_size == 128:
                self.pk = PK[0]
            elif self.key_bit_size == 256:
                self.pk = PK[1]
            else:
                print("The round_key size of block size 128 should be 128 or 256.", file=sys.stderr)
                sys.exit(1)
        elif self.block_bit_size == 256:
            self.pl = PL[1]
            self.pr = PR[1]
            if self.key_bit_size == 256:
                self.pk = PK[2]
            else:
                print("The round_key size of block size 256 should be 256.", file=sys.stderr)
                sys.exit(1)
        else:
            print("The block size should be 128 or 256.", file=sys.stderr)
            sys.exit(1)

    def round_initialization(self):
        left_state = ComponentState([INPUT_PLAINTEXT], [list(range(self.half_block_bit_size))])
        right_state = ComponentState(
            [INPUT_PLAINTEXT],
            [list(range(self.half_block_bit_size, self.block_bit_size))],
        )
        key_0 = ComponentState([INPUT_KEY], [list(range(self.key_block_size))])
        key_1 = ComponentState([INPUT_KEY], [list(range(self.key_block_size, self.key_block_size * 2))])
        key_2 = ComponentState([INPUT_KEY], [list(range(self.key_block_size * 2, self.key_block_size * 3))])
        key_3 = ComponentState([INPUT_KEY], [list(range(self.key_block_size * 3, self.key_block_size * 4))])
        round_key = ComponentState([INPUT_KEY], [list(range(self.block_bit_size))])

        return left_state, right_state, key_0, key_1, key_2, key_3, round_key

    def round_function(self, state_left, state_right, round_key):
        # state xor round_key
        self.add_XOR_component(
            state_left.id + state_right.id + round_key.id,
            state_left.input_bit_positions + state_right.input_bit_positions + round_key.input_bit_positions,
            self.block_bit_size,
        )
        state_left = ComponentState([self.get_current_component_id()], [list(range(self.half_block_bit_size))])
        state_right = ComponentState(
            [self.get_current_component_id()],
            [list(range(self.half_block_bit_size, self.block_bit_size))],
        )

        # sbox_n(state_left)
        ids = []
        window_size = SBOX_SIZE
        n = int(self.half_block_bit_size / window_size)
        for i in range(n):
            self.add_SBOX_component(
                state_left.id,
                [state_left.input_bit_positions[0][i * window_size : (i + 1) * window_size]],
                window_size,
                SBOX,
            )
            ids.append(self.get_current_component_id())
        state_left = ComponentState(ids, [list(range(window_size))] * n)

        # sbox_n(state_right)
        ids = []
        window_size = SBOX_SIZE
        n = int(self.half_block_bit_size / window_size)
        for i in range(n):
            self.add_SBOX_component(
                state_right.id,
                [state_right.input_bit_positions[0][i * window_size : (i + 1) * window_size]],
                window_size,
                SBOX,
            )
            ids.append(self.get_current_component_id())
        state_right = ComponentState(ids, [list(range(window_size))] * n)

        self.add_linear_layer_component(
            state_left.id + state_right.id,
            state_left.input_bit_positions + state_right.input_bit_positions,
            self.block_bit_size,
            generate_ublock_matrix(self.block_bit_size, 4, 8, 20),
        )

        linear_layer_id = self.get_current_component_id()
        state_left = ComponentState([linear_layer_id], [list(range(0, self.block_bit_size // 2))])
        state_right = ComponentState(
            [linear_layer_id],
            [list(range(self.block_bit_size // 2, self.block_bit_size))],
        )

        return state_left, state_right

    def key_schedule(self, key_0, key_1, key_2, key_3, RC):
        # K0||K1 = PK(K0||K1)
        self.add_word_permutation_component(
            key_0.id + key_1.id,
            key_0.input_bit_positions + key_1.input_bit_positions,
            self.key_block_size * 2,
            self.pk,
            PK_WORD_SIZE,
        )
        key_0 = ComponentState([self.get_current_component_id()], [list(range(self.key_block_size))])
        key_1 = ComponentState(
            [self.get_current_component_id()],
            [list(range(self.key_block_size, self.key_block_size * 2))],
        )

        # K2 = K2 xor sbox_k(K0 xor RC)
        self.add_constant_component(RC_SIZE, RC)
        round_constant = ComponentState([self.get_current_component_id()], [list(range(RC_SIZE))])
        if self.key_block_size == RC_SIZE:
            self.add_XOR_component(
                key_0.id + round_constant.id,
                key_0.input_bit_positions + round_constant.input_bit_positions,
                RC_SIZE,
            )
            temp = ComponentState([self.get_current_component_id()], [list(range(self.key_block_size))])
            ids = []
            window_size = SBOX_SIZE
            n = int(self.key_block_size / window_size)
            for i in range(n):
                self.add_SBOX_component(
                    temp.id,
                    [list(range(i * window_size, (i + 1) * window_size))],
                    window_size,
                    SBOX,
                )
                ids.append(self.get_current_component_id())
            temp = ComponentState(ids, [list(range(window_size))] * n)
        else:
            key_0_left = ComponentState(key_0.id, [list(range(RC_SIZE))])
            key_0_right = ComponentState(key_0.id, [list(range(RC_SIZE, self.key_block_size))])
            self.add_XOR_component(
                key_0_left.id + round_constant.id,
                key_0_left.input_bit_positions + round_constant.input_bit_positions,
                RC_SIZE,
            )
            temp = ComponentState([self.get_current_component_id()], [list(range(RC_SIZE))])
            ids = []
            window_size = SBOX_SIZE
            n = int(RC_SIZE / window_size)
            for i in range(n):
                self.add_SBOX_component(
                    temp.id,
                    [list(range(i * window_size, (i + 1) * window_size))],
                    window_size,
                    SBOX,
                )
                ids.append(self.get_current_component_id())
            n = int((self.key_block_size - RC_SIZE) / window_size)
            for i in range(n):
                self.add_SBOX_component(
                    key_0_right.id,
                    [key_0_right.input_bit_positions[0][i * window_size : (i + 1) * window_size]],
                    window_size,
                    SBOX,
                )
                ids.append(self.get_current_component_id())
            temp = ComponentState(ids, [list(range(window_size))] * int(self.key_block_size / window_size))
        self.add_XOR_component(
            key_2.id + temp.id,
            key_2.input_bit_positions + temp.input_bit_positions,
            self.key_block_size,
        )
        key_2 = ComponentState([self.get_current_component_id()], [list(range(self.key_block_size))])

        # K3 = K3 xor sbox_tk(K1)
        ids = []
        window_size = SBOX_SIZE
        n = int(self.key_block_size / window_size)
        for i in range(n):
            self.add_SBOX_component(
                key_1.id,
                [key_1.input_bit_positions[0][i * window_size : (i + 1) * window_size]],
                window_size,
                SBOX_TK,
            )
            ids.append(self.get_current_component_id())
        temp = ComponentState(ids, [list(range(window_size))] * n)
        self.add_XOR_component(
            key_3.id + temp.id,
            key_3.input_bit_positions + temp.input_bit_positions,
            self.key_block_size,
        )
        key_3 = ComponentState([self.get_current_component_id()], [list(range(self.key_block_size))])

        # K = K2 || K3 || K1 || K0
        if self.key_bit_size == self.block_bit_size:
            round_key = ComponentState(
                key_2.id + key_3.id + key_1.id + key_0.id,
                key_2.input_bit_positions
                + key_3.input_bit_positions
                + key_1.input_bit_positions
                + key_0.input_bit_positions,
            )
        else:
            round_key = ComponentState(
                key_2.id + key_3.id,
                key_2.input_bit_positions + key_3.input_bit_positions,
            )

        return key_2, key_3, key_1, key_0, round_key