
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
from claasp.utils.utils import extract_inputs
from claasp.utils.integer_functions import wordlist_to_int
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

permutation = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8]
PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 64, 'key_bit_size': 128, 'number_of_rounds': 16},
    {'block_bit_size': 128, 'key_bit_size': 128, 'number_of_rounds': 20},
]
sbox = [
    [12, 10, 13, 3, 14, 11, 15, 7, 8, 9, 1, 5, 0, 2, 4, 6],
    [1, 0, 5, 3, 14, 2, 15, 7, 13, 10, 9, 11, 12, 8, 4, 6]
]
M = [
    [0, 1, 1, 1],
    [1, 0, 1, 1],
    [1, 1, 0, 1],
    [1, 1, 1, 0]
]
sub_permutation = [
    [4, 1, 6, 3, 0, 5, 2, 7],
    [1, 6, 7, 0, 5, 2, 3, 4],
    [2, 3, 4, 1, 6, 7, 0, 5],
    [7, 4, 1, 2, 3, 0, 5, 6]
]
inverse_sub_permutation = [
    [4, 1, 6, 3, 0, 5, 2, 7],
    [3, 0, 5, 6, 7, 4, 1, 2],
    [6, 3, 0, 1, 2, 7, 4, 5],
    [5, 2, 3, 4, 1, 6, 7, 0]
]
round_constants = [
    [
        [0, 0, 1, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 1],
        [1, 1, 1, 1]
    ],
    [
        [0, 1, 1, 0],
        [1, 0, 1, 0],
        [1, 0, 0, 0],
        [1, 0, 0, 0]
    ],
    [
        [1, 0, 0, 0],
        [0, 1, 0, 1],
        [1, 0, 1, 0],
        [0, 0, 1, 1]
    ],
    [
        [0, 0, 0, 0],
        [1, 0, 0, 0],
        [1, 1, 0, 1],
        [0, 0, 1, 1]
    ],
    [
        [0, 0, 0, 1],
        [0, 0, 1, 1],
        [0, 0, 0, 1],
        [1, 0, 0, 1]
    ],
    [
        [1, 0, 0, 0],
        [1, 0, 1, 0],
        [0, 0, 1, 0],
        [1, 1, 1, 0]
    ],
    [
        [0, 0, 0, 0],
        [0, 0, 1, 1],
        [0, 1, 1, 1],
        [0, 0, 0, 0]
    ],
    [
        [0, 1, 1, 1],
        [0, 0, 1, 1],
        [0, 1, 0, 0],
        [0, 1, 0, 0]
    ],
    [
        [1, 0, 1, 0],
        [0, 1, 0, 0],
        [0, 0, 0, 0],
        [1, 0, 0, 1]
    ],
    [
        [0, 0, 1, 1],
        [1, 0, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 1, 0]
    ],
    [
        [0, 0, 1, 0],
        [1, 0, 0, 1],
        [1, 0, 0, 1],
        [1, 1, 1, 1]
    ],
    [
        [0, 0, 1, 1],
        [0, 0, 0, 1],
        [1, 1, 0, 1],
        [0, 0, 0, 0]
    ],
    [
        [0, 0, 0, 0],
        [1, 0, 0, 0],
        [0, 0, 1, 0],
        [1, 1, 1, 0]
    ],
    [
        [1, 1, 1, 1],
        [1, 0, 1, 0],
        [1, 0, 0, 1],
        [1, 0, 0, 0]
    ],
    [
        [1, 1, 1, 0],
        [1, 1, 0, 0],
        [0, 1, 0, 0],
        [1, 1, 1, 0]
    ],
    [
        [0, 1, 1, 0],
        [1, 1, 0, 0],
        [1, 0, 0, 0],
        [1, 0, 0, 1]
    ],
    [
        [0, 1, 0, 0],
        [0, 1, 0, 1],
        [0, 0, 1, 0],
        [1, 0, 0, 0]
    ],
    [
        [0, 0, 1, 0],
        [0, 0, 0, 1],
        [1, 1, 1, 0],
        [0, 1, 1, 0]
    ],
    [
        [0, 0, 1, 1],
        [1, 0, 0, 0],
        [1, 1, 0, 1],
        [0, 0, 0, 0]
    ]
]
reference_code = f"""
def midori_encrypt(plaintext, key):
    from claasp.utils.integer_functions import (int_to_wordlist,
                                             wordlist_to_int,
                                             bytearray_to_wordlist,
                                             bytearray_to_int,
                                             wordlist_to_bytearray)

    plaintext_size = {{0}}
    key_size = {{1}}
    rounds = {{2}}

    round_constants = {round_constants}
    M = {M}
    permutation = {permutation}
    sbox = {sbox}
    sub_permutation = {sub_permutation}
    inverse_sub_permutation = {inverse_sub_permutation}

    def matrix_product(A, B):
        result = [0] * len(B)

        for i in range(len(A)):
            for k in range(len(B)):
                result[i] ^= A[i][k] * B[k]

        return result

    def key_add(S, round_key):
        word_size = plaintext_size // 16

        S_int = wordlist_to_int(S, word_size)

        S_int ^= round_key

        S[:] = int_to_wordlist(S_int, word_size, plaintext_size)

    def sub_cell(S):
        if plaintext_size == 64:
            for i in range(16):
                S[i] = sbox[0][S[i]]
        else:
            for i in range(16):
                S_bits = int_to_wordlist(S[i], 1, 8)

                S_permuted = [S_bits[p] for p in sub_permutation[i%4]]

                new_S_value = sbox[1][wordlist_to_int(S_permuted[:4], 1)] * 2**4 +\
                              sbox[1][wordlist_to_int(S_permuted[4:], 1)]

                new_S_bits = int_to_wordlist(new_S_value, 1, 8)
                S_output_permutation = [new_S_bits[p] for p in inverse_sub_permutation[i%4]]

                S[i] = wordlist_to_int(S_output_permutation, 1)

    def shuffle_cell(S):
        S[:] = [S[i] for i in permutation]

    def mix_columns(S):
        for i in range(4):
            column = S[i*4: i*4 + 4]
            S[i*4: i*4 + 4] = matrix_product(M, column)

    def round_key(k, i):
        word_size = plaintext_size // 16

        if plaintext_size == 64:
            if i % 2 == 0:
                k_in = k >> 64
            else:
                k_in = k % 2**64
        else:
            k_in = k

        k_words = int_to_wordlist(k_in, word_size, plaintext_size)

        for j in range(16):
            row = j % 4
            col = j // 4

            k_words[j] ^= round_constants[i][row][col]

        return wordlist_to_int(k_words, word_size)

    if plaintext_size != 64 and plaintext_size != 128:
        raise ValueError("Plaintext size must either be 64 or 128 bits.")
    if key_size != 128:
        raise ValueError("Key size must be 64 bits.")

    word_size = plaintext_size // 16

    S = bytearray_to_wordlist(plaintext, word_size, plaintext_size)
    k = bytearray_to_int(key)

    if plaintext_size == 64:
        WK = (k >> 64) ^ (k % 2**64)
    else:
        WK = k

    key_add(S, WK)

    for i in range(rounds - 1):
        rk = round_key(k, i)

        sub_cell(S)
        shuffle_cell(S)
        mix_columns(S)
        key_add(S, rk)

    sub_cell(S)
    key_add(S, WK)

    return wordlist_to_bytearray(S, word_size)
"""


class MidoriBlockCipher(Cipher):
    """
    Construct an instance of the MidoriBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
        sage: midori = MidoriBlockCipher()
        sage: midori.number_of_rounds
        16

        sage: midori.component_from(0, 0).id
        'xor_0_0'
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=0):
        self.block_bit_size = block_bit_size
        self.word_size = self.block_bit_size // 16

        if self.block_bit_size == 64:
            self.polynomial = 19
        else:
            self.polynomial = 283

        if number_of_rounds == 0:
            n = None

            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size and parameters['key_bit_size'] == key_bit_size:
                    n = parameters['number_of_rounds']
                    break

            if n is None:
                raise ValueError("No available number of rounds for the given parameters.")
        else:
            n = number_of_rounds

        super().__init__(family_name="midori", cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, key_bit_size],
                         cipher_output_bit_size=self.block_bit_size,
                         cipher_reference_code=reference_code.format(self.block_bit_size, key_bit_size, n))

        data = [INPUT_PLAINTEXT], [list(range(self.block_bit_size))]
        key_id = INPUT_KEY

        self.add_round()

        if self.block_bit_size == 64:
            WK_id = self.add_XOR_component([key_id], [list(range(key_bit_size))], 64).id
        else:
            WK_id = key_id

        data = self.key_add(data, WK_id)

        for round_number in range(n - 1):
            round_key_id = self.round_key(key_id, round_number)

            data = self.sub_cell(data)
            data = self.shuffle_cell(data)
            data = self.mix_column(data)
            data = self.key_add(data, round_key_id)

            self.add_round_output_component(data[0], data[1], self.block_bit_size)
            self.add_round_key_output_component([round_key_id], [list(range(self.block_bit_size))], self.block_bit_size)

            self.add_round()

        data = self.sub_cell(data)
        data = self.key_add(data, WK_id)

        self.add_round_output_component(data[0], data[1], self.block_bit_size)

        self.add_cipher_output_component(data[0], data[1], self.block_bit_size)

    def key_add(self, data, round_key_id):
        new_data_id = self.add_XOR_component(data[0] + [round_key_id],
                                             data[1] + [list(range(self.block_bit_size))],
                                             self.block_bit_size).id

        return [new_data_id], [list(range(self.block_bit_size))]

    def mix_column(self, data):
        column_size = self.block_bit_size // 4
        new_data_id_list = [''] * 4

        for i in range(4):
            data_id_list, data_bit_positions = \
                extract_inputs(*data, list(range(i * column_size, (i + 1) * column_size)))
            new_data_id_list[i] = self.add_mix_column_component(data_id_list, data_bit_positions, column_size,
                                                                [M, self.polynomial, self.word_size]).id

        return new_data_id_list, [list(range(column_size))] * 4

    def round_key(self, key_id, i):
        round_constant_value = wordlist_to_int([round_constants[i][j % 4][j // 4] for j in range(16)], self.word_size)

        round_constant_id = self.add_constant_component(self.block_bit_size, round_constant_value).id

        if self.block_bit_size == 64:
            xor_id = self.add_XOR_component([key_id, round_constant_id],
                                            [list(range((i % 2) * 64, ((i % 2) + 1) * 64)), list(range(64))],
                                            64).id

        else:
            xor_id = self.add_XOR_component([key_id, round_constant_id], [list(range(128))] * 2, 128).id

        return xor_id

    def shuffle_cell(self, data):
        new_data_id = self.add_word_permutation_component(data[0], data[1],
                                                          self.block_bit_size, permutation,
                                                          self.word_size).id

        return [new_data_id], [list(range(self.block_bit_size))]

    def sub_cell(self, data):
        new_data_id_list = [''] * 16

        if self.block_bit_size == 64:
            for i in range(16):
                data_id_list, data_bit_positions = extract_inputs(*data, list(range(i * 4, (i + 1) * 4)))
                new_data_id_list[i] = self.add_SBOX_component(data_id_list, data_bit_positions, 4, sbox[0]).id

        else:
            for i in range(16):
                data_id_list, data_bit_positions = \
                    extract_inputs(*data, list(range(i * self.word_size, (i + 1) * self.word_size)))
                p = [sub_permutation[i % 4].index(j) for j in range(8)]
                permutated_data_word_id = self.add_permutation_component(data_id_list,
                                                                         data_bit_positions,
                                                                         self.word_size, p).id

                sbox_high_output = self.add_SBOX_component([permutated_data_word_id], [list(range(4))], 4, sbox[1]).id
                sbox_low_output = self.add_SBOX_component([permutated_data_word_id], [list(range(4, 8))], 4, sbox[1]).id

                perm = [inverse_sub_permutation[i % 4].index(j) for j in range(8)]
                new_data_id_list[i] = self.add_permutation_component([sbox_high_output, sbox_low_output],
                                                                     [list(range(4))] * 2, 8, perm).id

        return new_data_id_list, [list(range(self.word_size))] * 16
