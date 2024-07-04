
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


class SimeckBlockCipher(Cipher):
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

        sage: from claasp.ciphers.block_ciphers.simeck_block_cipher import SimeckBlockCipher
        sage: simon = SimeckBlockCipher()
        sage: simeck.number_of_rounds
        32

        sage: simeck.component_from(0, 0).id
        'intermediate_output_0_0'
    """

    def __init__(self, block_bit_size=32, key_bit_size=64, number_of_rounds=None, rotation_amounts=(-5, -1)):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.word_size = self.block_bit_size // 2
        self.rotation_amounts = rotation_amounts
        self.z = Z[WORDSIZE_TO_ZINDEX[self.word_size]]
        self.c = 2**self.word_size - 4

        if number_of_rounds is None:
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if parameters['block_bit_size'] == self.block_bit_size and \
                        parameters['key_bit_size'] == self.key_bit_size:
                    number_of_rounds = parameters['number_of_rounds']
                    break
            if number_of_rounds is None:
                raise ValueError("No available number of rounds for the given parameters.")

        super().__init__(family_name="simeck",
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
        # f(x) = (x & x <<< 5) ⊕ x <<< 1
        s5x = self.add_rotate_component([left[0]], [left[1]], self.word_size, self.rotation_amounts[0]).id
        x_and_s5x = self.add_AND_component([left[0], s5x], [list(range(self.word_size))] * 2, self.word_size).id
        s1x = self.add_rotate_component([left[0]], [left[1]], self.word_size, self.rotation_amounts[1]).id
        # Rk(x, y) = (y ⊕ f(x) ⊕ k, x)
        f_id = self.add_XOR_component([x_and_s5x, s1x], [list(range(self.word_size))] * 2, self.word_size).id
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
