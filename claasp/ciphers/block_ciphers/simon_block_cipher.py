
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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 32, 'key_bit_size': 64, 'number_of_rounds': 32},
    {'block_bit_size': 48, 'key_bit_size': 72, 'number_of_rounds': 36},
    {'block_bit_size': 48, 'key_bit_size': 96, 'number_of_rounds': 36},
    {'block_bit_size': 64, 'key_bit_size': 96, 'number_of_rounds': 42},
    {'block_bit_size': 64, 'key_bit_size': 128, 'number_of_rounds': 44},
    {'block_bit_size': 96, 'key_bit_size': 96, 'number_of_rounds': 52},
    {'block_bit_size': 96, 'key_bit_size': 144, 'number_of_rounds': 54},
    {'block_bit_size': 128, 'key_bit_size': 128, 'number_of_rounds': 68},
    {'block_bit_size': 128, 'key_bit_size': 192, 'number_of_rounds': 69},
    {'block_bit_size': 128, 'key_bit_size': 256, 'number_of_rounds': 72}
]
z = [
    4506230155203752166,
    2575579794259089498,
    3160415496042964403,
    3957284701066611983,
    3781244162168104175
]
conf = {
    16: {4: 0},
    24: {3: 0, 4: 1},
    32: {3: 2, 4: 3},
    48: {2: 2, 3: 3},
    64: {2: 2, 3: 3, 4: 4}
}
reference_code = """
def simon_encrypt(plaintext, key):
    from claasp.utils.integer_functions import bytearray_to_wordlist, wordlist_to_bytearray, lor, ror

    plaintext_size = {0}
    key_size = {1}
    rounds = {2}

    word_size = plaintext_size // 2
    key_size_in_words = key_size // word_size

    rotation_amounts = {3}
    z = {4}
    c = 2**word_size - 4

    def generate_round_key(key, round_keys, r):
        if r < key_size_in_words:
            return key[key_size_in_words - r - 1]

        i = r - key_size_in_words

        op = ror(round_keys[i + key_size_in_words - 1], 3, word_size)

        if key_size_in_words == 4:
            op = op ^ round_keys[i+1]

        return c ^ ((z >> (61 - (i % 62))) & 1) ^ round_keys[i] ^ op ^ ror(op, 1, word_size)

    def feistel_function(data, round_key):
        new_x = data[1] ^ f(data) ^ round_key

        return [new_x, data[0]]

    def f(data):
        if rotation_amounts[0] < 0:
            s1 = lor(data[0], -rotation_amounts[0], word_size)
        else:
            s1 = ror(data[0], rotation_amounts[0], word_size)

        if rotation_amounts[1] < 0:
            s8 = lor(data[0], -rotation_amounts[1], word_size)
        else:
            s8 = ror(data[0], rotation_amounts[1], word_size)

        if rotation_amounts[2] < 0:
            s2 = lor(data[0], -rotation_amounts[2], word_size)
        else:
            s2 = ror(data[0], rotation_amounts[2], word_size)

        return (s1 & s8) ^ s2

    data = bytearray_to_wordlist(plaintext, word_size)
    k = bytearray_to_wordlist(key, word_size, key_size)

    round_keys = [0] * rounds

    for r in range(rounds):
        round_keys[r] = generate_round_key(k, round_keys, r)
        data = feistel_function(data, round_keys[r])

    return wordlist_to_bytearray(data, word_size)

"""


class SimonBlockCipher(Cipher):
    """
    Construct an instance of the SimonBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `64`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is None
    - ``rotation_amount`` -- **list** (default: `[-1, -8, -2]`); the list containing the 3 rotation amounts for the
      round function

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: simon = SimonBlockCipher()
        sage: simon.number_of_rounds
        32

        sage: simon.component_from(0, 0).id
        'intermediate_output_0_0'
    """

    def __init__(self, block_bit_size=32, key_bit_size=64, number_of_rounds=None, rotation_amounts=[-1, -8, -2]):
        self.block_bit_size = block_bit_size
        self.word_size = self.block_bit_size // 2
        self.key_size_in_words = key_bit_size // self.word_size
        self.rotation_amounts = rotation_amounts.copy()
        self.z = z[conf[self.word_size][self.key_size_in_words]]
        self.c = 2**self.word_size - 4

        if number_of_rounds is None:
            n = None

            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size and \
                        parameters['key_bit_size'] == key_bit_size:
                    n = parameters['number_of_rounds']
                    break

            if n is None:
                raise ValueError("No available number of rounds for the given parameters.")
        else:
            n = number_of_rounds

        super().__init__(family_name="simon",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, key_bit_size],
                         cipher_output_bit_size=self.block_bit_size,
                         cipher_reference_code=reference_code.format(block_bit_size, key_bit_size, n,
                                                                     self.rotation_amounts, self.z))

        data = [INPUT_PLAINTEXT, INPUT_PLAINTEXT], \
               [list(range(self.word_size)), list(range(self.word_size, 2 * self.word_size))]

        round_keys = [None] * n

        for round_number in range(n):
            self.add_round()

            self.generate_round_key(round_keys, round_number)

            data = self.feistel_function(data, round_keys[round_number])

        self.add_cipher_output_component(*data, self.block_bit_size)

    def f(self, x):
        # f(x) = (x <<< 1 & x <<< 8) ⊕ x <<< 2
        s1_x = self.add_rotate_component([x[0]], [x[1]], self.word_size, self.rotation_amounts[0]).id
        s8_x = self.add_rotate_component([x[0]], [x[1]], self.word_size, self.rotation_amounts[1]).id
        s2_x = self.add_rotate_component([x[0]], [x[1]], self.word_size, self.rotation_amounts[2]).id

        s1_and_s8 = self.add_AND_component([s1_x, s8_x], [list(range(self.word_size))] * 2, self.word_size).id

        return self.add_XOR_component([s1_and_s8, s2_x], [list(range(self.word_size))] * 2, self.word_size).id

    def feistel_function(self, data, round_key):
        # Rk(x, y) = (y ⊕ f(x) ⊕ k, x)
        f_id = self.f((data[0][0], data[1][0]))
        new_x_id = self.add_XOR_component([data[0][1], f_id, round_key[0]],
                                          [data[1][1], list(range(self.word_size)), round_key[1]],
                                          self.word_size).id

        self.add_round_output_component([new_x_id, data[0][0]],
                                        [list(range(self.word_size)), data[1][0]],
                                        self.block_bit_size).id

        return [new_x_id, data[0][0]], [list(range(self.word_size)), data[1][0]]

    def generate_round_key(self, round_keys, round_number):
        if round_number < self.key_size_in_words:
            key_size = self.key_size_in_words - round_number - 1

            self.add_round_key_output_component(
                [INPUT_KEY],
                [list(range(self.word_size * key_size, self.word_size * (key_size + 1)))],
                self.word_size).id
            round_keys[round_number] = \
                INPUT_KEY, list(range(self.word_size * key_size, self.word_size * (key_size + 1)))

        else:
            i = round_number - self.key_size_in_words

            # c ^ z[j][i]
            round_constant = self.add_constant_component(
                self.word_size, self.c ^ ((self.z >> (61 - (i % 62))) & 1)).id

            op = self.add_rotate_component([round_keys[i + self.key_size_in_words - 1][0]],
                                           [round_keys[i + self.key_size_in_words - 1][1]],
                                           self.word_size, 3).id

            if self.key_size_in_words == 4:
                op = self.add_XOR_component([op, round_keys[i + 1][0]],
                                            [list(range(self.word_size)), round_keys[i + 1][1]],
                                            self.word_size).id

            rot_id = self.add_rotate_component([op], [list(range(self.word_size))], self.word_size, 1).id

            xor_id = self.add_XOR_component([round_constant, round_keys[i][0], op, rot_id],
                                            [list(range(self.word_size)), round_keys[i][1]] +
                                            [list(range(self.word_size))] * 2,
                                            self.word_size).id

            self.add_round_key_output_component([xor_id], [list(range(self.word_size))], self.word_size).id
            round_keys[round_number] = xor_id, list(range(self.word_size))
