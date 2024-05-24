
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
wordsize2zindex = {
    16: {4: 0},
    24: {3: 0, 4: 1},
    32: {3: 2, 4: 3},
    48: {2: 2, 3: 3},
    64: {2: 2, 3: 3, 4: 4}
}


class SimonSboxBlockCipher(Cipher):
    # """
    # Construct an instance of the SimonBlockCipher class.

    # This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    # INPUT:

    # - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher
    # - ``key_bit_size`` -- **integer** (default: `64`); cipher key bit size of the cipher
    # - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds of the cipher. The cipher uses the
    #   corresponding amount given the other parameters (if available) when number_of_rounds is None
    # - ``rotation_amount`` -- **list** (default: `[-1, -8, -2]`); the list containing the 3 rotation amounts for the
    #   round function

    # EXAMPLES::

    #     sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
    #     sage: simon = SimonBlockCipher()
    #     sage: simon.number_of_rounds
    #     32

    #     sage: simon.component_from(0, 0).id
    #     'intermediate_output_0_0'
    # """

    def __init__(self, block_bit_size=32, key_bit_size=64, number_of_rounds=None, rotation_amounts=[-1, -8, -2]):
        self.block_bit_size = block_bit_size
        self.word_size = self.block_bit_size // 2
        self.key_size_in_words = key_bit_size // self.word_size
        self.rotation_amounts = rotation_amounts[:]
        self.z = z[wordsize2zindex[self.word_size][self.key_size_in_words]]
        self.c = 2**self.word_size - 4
        self.number_of_sboxes = self.block_bit_size // 8

        if number_of_rounds is None:
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size and \
                        parameters['key_bit_size'] == key_bit_size:
                    number_of_rounds = parameters['number_of_rounds']
                    break

            if number_of_rounds is None:
                raise ValueError("No available number of rounds for the given parameters.")

        super().__init__(family_name="simon",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        x = INPUT_PLAINTEXT, list(range(self.word_size))
        y = INPUT_PLAINTEXT, list(range(self.word_size, 2 * self.word_size))

        round_keys = [None] * n

        for round_number in range(n):
            self.add_round()
            self.generate_round_key(round_keys, round_number)
            x, y = self.feistel_function(x, y, round_keys[round_number])

        self.add_cipher_output_component([x[0], y[0]], [x[1], y[1]], self.block_bit_size)

    def f(self, x):
        # f(x) = ((x <<< 1) & (x <<< 8)) ⊕ (x <<< 2)
        indices = (1, 8, 2, 9, 3, 10, 4, 11, 5)
        sboxes_ids = []
        for _ in range(self.number_of_sboxes):
            sbox_positions = list(map(int.__add__(i*4), indices))
            sboxes.append(self.add_SBOX_component(x[0], [x[1][:8]], ).id)

        return sboxes_ids, [list(range(8)) for _ in range(self.number_of_sboxes)]

    def feistel_function(self, x, y, k):
        # Rk(x, y) = (y ⊕ f(x) ⊕ k, x)
        sboxes = self.f(x)
        new_x_id = self.add_XOR_component([y[0], *sboxes[0], k[0]], [y[1], *sboxes[1], k[1]],
                                          self.word_size).id

        self.add_round_output_component([new_x_id, x.id], [list(range(self.word_size)), x[0]],
                                        self.block_bit_size).id

        return (new_x_id, list(range(self.word_size))), (x[0], x[1])

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
