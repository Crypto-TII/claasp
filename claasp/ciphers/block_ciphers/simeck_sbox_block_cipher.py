
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
    {'block_bit_size': 48, 'key_bit_size': 96, 'number_of_rounds': 36},
    {'block_bit_size': 64, 'key_bit_size': 128, 'number_of_rounds': 44}
]
Z = [
    5557826286501673759,
    3114073359753873471
]
WORDSIZE_TO_ZINDEX = {
    16: 0,
    24: 0,
    32: 1
}
SBOX = [0, 0, 0, 1, 0, 0, 2, 3, 0, 0, 0, 1, 4, 4, 6, 7, 0, 0, 0, 1, 0, 0, 2, 3, 8, 8, 8, 9, 12, 12, 14, 15, 0, 0,
        0, 1, 0, 0, 2, 3, 0, 0, 0, 1, 4, 4, 6, 7, 16, 16, 16, 17, 16, 16, 18, 19, 24, 24, 24, 25, 28, 28, 30,
        31, 0, 0, 0, 1, 0, 0, 2, 3, 0, 0, 0, 1, 4, 4, 6, 7, 0, 0, 0, 1, 0, 0, 2, 3, 8, 8, 8, 9, 12, 12, 14, 15,
        32, 32, 32, 33, 32, 32, 34, 35, 32, 32, 32, 33, 36, 36, 38, 39, 48, 48, 48, 49, 48, 48, 50, 51, 56, 56,
        56, 57, 60, 60, 62, 63, 0, 0, 0, 1, 0, 0, 2, 3, 0, 0, 0, 1, 4, 4, 6, 7, 0, 0, 0, 1, 0, 0, 2, 3, 8, 8, 8,
        9, 12, 12, 14, 15, 0, 0, 0, 1, 0, 0, 2, 3, 0, 0, 0, 1, 4, 4, 6, 7, 16, 16, 16, 17, 16, 16, 18, 19, 24,
        24, 24, 25, 28, 28, 30, 31, 64, 64, 64, 65, 64, 64, 66, 67, 64, 64, 64, 65, 68, 68, 70, 71, 64, 64, 64,
        65, 64, 64, 66, 67, 72, 72, 72, 73, 76, 76, 78, 79, 96, 96, 96, 97, 96, 96, 98, 99, 96, 96, 96, 97, 100,
        100, 102, 103, 112, 112, 112, 113, 112, 112, 114, 115, 120, 120, 120, 121, 124, 124, 126, 127, 0, 0, 0,
        1, 0, 0, 2, 3, 0, 0, 0, 1, 4, 4, 6, 7, 0, 0, 0, 1, 0, 0, 2, 3, 8, 8, 8, 9, 12, 12, 14, 15, 0, 0, 0, 1,
        0, 0, 2, 3, 0, 0, 0, 1, 4, 4, 6, 7, 16, 16, 16, 17, 16, 16, 18, 19, 24, 24, 24, 25, 28, 28, 30, 31, 0,
        0, 0, 1, 0, 0, 2, 3, 0, 0, 0, 1, 4, 4, 6, 7, 0, 0, 0, 1, 0, 0, 2, 3, 8, 8, 8, 9, 12, 12, 14, 15, 32, 32,
        32, 33, 32, 32, 34, 35, 32, 32, 32, 33, 36, 36, 38, 39, 48, 48, 48, 49, 48, 48, 50, 51, 56, 56, 56, 57,
        60, 60, 62, 63, 128, 128, 128, 129, 128, 128, 130, 131, 128, 128, 128, 129, 132, 132, 134, 135, 128,
        128, 128, 129, 128, 128, 130, 131, 136, 136, 136, 137, 140, 140, 142, 143, 128, 128, 128, 129, 128, 128,
        130, 131, 128, 128, 128, 129, 132, 132, 134, 135, 144, 144, 144, 145, 144, 144, 146, 147, 152, 152, 152,
        153, 156, 156, 158, 159, 192, 192, 192, 193, 192, 192, 194, 195, 192, 192, 192, 193, 196, 196, 198, 199,
        192, 192, 192, 193, 192, 192, 194, 195, 200, 200, 200, 201, 204, 204, 206, 207, 224, 224, 224, 225, 224,
        224, 226, 227, 224, 224, 224, 225, 228, 228, 230, 231, 240, 240, 240, 241, 240, 240, 242, 243, 248, 248,
        248, 249, 252, 252, 254, 255]


class SimeckSboxBlockCipher(Cipher):
    """
    Construct an instance of the SimeckBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `64`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is None
    - ``rotation_amount`` -- **tuple** (default: `(-5, -1)`); the tuple containing the 3 rotation amounts for the
      round function

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.simeck_sbox_block_cipher import SimeckSboxBlockCipher
        sage: simeck_sbox = SimeckSboxBlockCipher()
        sage: simeck_sbox.number_of_rounds
        32

        sage: simeck_sbox.component_from(0, 0).id
        'sbox_0_0'
    """

    def __init__(self, block_bit_size=32, key_bit_size=64, number_of_rounds=None, rotation_amounts=(-5, -1)):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.word_size = self.block_bit_size // 2
        self.rotation_amounts = rotation_amounts
        self.z = Z[WORDSIZE_TO_ZINDEX[self.word_size]]
        self.c = 2**self.word_size - 4
        self.number_of_sboxes = self.word_size // 8

        if number_of_rounds is None:
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size and \
                        parameters['key_bit_size'] == self.key_bit_size:
                    number_of_rounds = parameters['number_of_rounds']
                    break
            if number_of_rounds is None:
                raise ValueError("No available number of rounds for the given parameters.")

        super().__init__(family_name="simeck_sbox",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        left = INPUT_PLAINTEXT, list(range(self.word_size))
        right = INPUT_PLAINTEXT, list(range(self.word_size, 2 * self.word_size))
        keys_buffer = []
        for i in range(4):
            keys_buffer.append((INPUT_KEY, list(range(self.word_size * i, self.word_size * (i + 1)))))

        for round_number in range(number_of_rounds - 1):
            self.add_round()
            left, right = self.feistel_function(left, right, keys_buffer[3])
            self.add_round_output_component([left[0], right[0]], [left[1], right[1]], self.block_bit_size)
            keys_buffer = self.update_keys_buffer(keys_buffer, round_number)
            self.add_round_key_output_component([keys_buffer[3][0]], [keys_buffer[3][1]], self.word_size)
        self.add_round()
        left, right = self.feistel_function(left, right, keys_buffer[3])
        self.add_cipher_output_component([left[0], right[0]], [left[1], right[1]], self.block_bit_size)

    def feistel_function(self, left, right, round_key):
        # g(x) = (x & x <<< 5) ⊕ (x <<< 1)
        # ┌ both for input and output positions
        # │ output have not the last element
        positions_pattern = (0, 5, 10, 15, 20, 25, 30, 35, 40)
        output_ids = [""] * self.word_size
        output_positions = [0] * self.word_size
        for i in range(self.number_of_sboxes):
            sbox_input_positions = [left[1][(position + 8*i) % self.word_size] for position in positions_pattern]
            sbox_id = self.add_SBOX_component([left[0]], [sbox_input_positions], 8, SBOX).id
            sbox_output_positions = [(position + 8*i) % self.word_size for position in positions_pattern[:-1]]
            for j, sbox_output_position in enumerate(sbox_output_positions):
                output_ids[sbox_output_position] = sbox_id
                output_positions[sbox_output_position] = j
        sboxes_ids = [output_ids[0]]
        sboxes_positions = [[output_positions[0]]]
        for i in range(1, self.word_size):
            if output_ids[i] != sboxes_ids[-1]:
                sboxes_ids.append(output_ids[i])
                sboxes_positions.append([output_positions[i]])
            else:
                sboxes_positions[-1].append(output_positions[i])
        s1_left_input_positions = left[1][1:] + [left[1][0]]
        f_id = self.add_XOR_component([*sboxes_ids, left[0]],
                                      [*sboxes_positions, s1_left_input_positions],
                                      self.word_size).id
        # Rk(x, y) = (y ⊕ f(x) ⊕ k, x)
        new_left_id = self.add_XOR_component([right[0], f_id, round_key[0]],
                                             [right[1], list(range(self.word_size)), round_key[1]],
                                             self.word_size).id

        return (new_left_id, list(range(self.word_size))), left

    def update_keys_buffer(self, keys_buffer, round_number):
        # c ^ z[j][i]
        round_constant_id = self.add_constant_component(self.word_size, self.c ^ ((self.z >> round_number) & 1)).id
        round_constant = round_constant_id, list(range(self.word_size))
        new_key_left, keys_buffer[3] = self.feistel_function(keys_buffer[2], keys_buffer[3], round_constant)
        keys_buffer[2] = keys_buffer[1]
        keys_buffer[1] = keys_buffer[0]
        keys_buffer[0] = new_key_left

        return keys_buffer
