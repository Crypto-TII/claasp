
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


import itertools

from claasp.cipher import Cipher
from claasp.utils.utils import get_ith_word
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 128, 'key_bit_size': 128, 'number_of_rounds': 24},
    {'block_bit_size': 128, 'key_bit_size': 192, 'number_of_rounds': 28},
    {'block_bit_size': 128, 'key_bit_size': 256, 'number_of_rounds': 32},
]
KEY_SCHEDULE_CONSTANTS = [
    0xc3efe9db,
    0x44626b02,
    0x79e27c8a,
    0x78df30ec,
    0x715ea49e,
    0xc785da0a,
    0xe04ef22a,
    0xe5c40957
]


def format_output(input_bit_positions_lst):
    for position in range(len(input_bit_positions_lst)):
        input_bit_positions = input_bit_positions_lst[position]
        new_input_bit_positions = []
        for j in range(4):
            sliced_input_bit_positions = input_bit_positions[(3 - j) * 8:(3 - j) * 8 + 8]
            new_input_bit_positions += sliced_input_bit_positions
        input_bit_positions_lst[position] = new_input_bit_positions

    return input_bit_positions_lst


def init_input(number_of_words, cipher_input, reorder_input_and_output):
    input_state = []
    for i in range(number_of_words):
        if reorder_input_and_output:
            input_bit_positions = [list(itertools.chain(
                *[get_ith_word(8, 4 * i + 4 - j - 1) for j in range(4)]))]
        else:
            input_bit_positions = [get_ith_word(32, i)]

        input_state_i = ComponentState(cipher_input, input_bit_positions)

        input_state.append(input_state_i)

    return input_state


class LeaBlockCipher(Cipher):
    """
    Construct an instance of the LeaBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `192`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``reorder_input_and_output`` -- **boolean** (default: `True`)

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
        sage: lea = LeaBlockCipher()
        sage: lea.number_of_rounds
        28

        sage: lea.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, block_bit_size=128, key_bit_size=192, number_of_rounds=0, reorder_input_and_output=True):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.WORD_SIZE = 32

        super().__init__(family_name="lea",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        number_of_rounds = self.get_numbers_of_rounds(number_of_rounds)

        left_rotations_list = [-1, -3, -6, -11, -13, -17]
        number_of_words_per_key = self.key_bit_size // self.WORD_SIZE

        internal_state = init_input(4, INPUT_PLAINTEXT, reorder_input_and_output)
        round_key_state = init_input(number_of_words_per_key, INPUT_KEY, reorder_input_and_output)

        for round_i in range(number_of_rounds):
            self.add_round()

            if key_bit_size == 128:
                delta_constant = KEY_SCHEDULE_CONSTANTS[round_i % 4]
                number_of_operations = 4
                round_key_state, round_key = self.get_ith_key128(round_key_state, round_i, number_of_operations,
                                                                 delta_constant, left_rotations_list)
            elif key_bit_size == 192:
                delta_constant = KEY_SCHEDULE_CONSTANTS[round_i % 6]
                number_of_operations = 6
                round_key_state, round_key = self.get_ith_key192(round_key_state, round_i, number_of_operations,
                                                                 delta_constant, left_rotations_list)
            elif key_bit_size == 256:
                delta_constant = KEY_SCHEDULE_CONSTANTS[round_i % 8]
                number_of_operations = 6
                round_key_state, round_key = self.get_ith_key256(round_key_state, round_i, number_of_operations,
                                                                 delta_constant, left_rotations_list)
            else:
                raise ValueError(f'Key bit size {key_bit_size} does not exists')

            internal_state = self.round_function(internal_state, round_key)
            self.add_intermediate_output_components(round_key,
                                                    internal_state,
                                                    number_of_rounds,
                                                    round_i,
                                                    reorder_input_and_output)

    def add_intermediate_output_components(self, round_key, internal_state,
                                           number_of_rounds, round_i, reorder_input_and_output):
        self.add_round_key_output_component([round_key[k].id for k in range(6)],
                                            [get_ith_word(self.WORD_SIZE, 0) for _ in range(6)],
                                            6 * self.WORD_SIZE)
        first_input_bit_positions = []
        if round_i == 0:
            for j in range(4):
                if j != 3:
                    first_input_bit_positions.append(get_ith_word(self.WORD_SIZE, 0))
                else:
                    first_input_bit_positions.append(internal_state[j].input_bit_positions[0])
        else:
            first_input_bit_positions = [get_ith_word(self.WORD_SIZE, 0) for _ in range(4)]

        if round_i == number_of_rounds - 1:
            if reorder_input_and_output:
                first_input_bit_positions = format_output(first_input_bit_positions)
            self.add_cipher_output_component([internal_state[k].id for k in range(4)],
                                             first_input_bit_positions,
                                             self.block_bit_size)
        else:
            self.add_round_output_component([internal_state[k].id for k in range(4)],
                                            first_input_bit_positions,
                                            self.block_bit_size)

    def get_ith_key128(self, key, round_i, number_of_operations, delta_constant, left_rotations_list):
        for operation in range(number_of_operations):
            delta_j = self.add_constant_component(self.WORD_SIZE, delta_constant)
            rot_j = self.add_rotate_component([delta_j.id], [get_ith_word(self.WORD_SIZE, 0)],
                                              self.WORD_SIZE, -(round_i + operation))
            mod_j = self.add_MODADD_component([key[operation].id] + [rot_j.id],
                                              key[operation].input_bit_positions + rot_j.input_bit_positions,
                                              self.WORD_SIZE)

            rot_c = self.add_rotate_component([mod_j.id], [get_ith_word(self.WORD_SIZE, 0)],
                                              self.WORD_SIZE, left_rotations_list[operation])
            key[operation] = rot_c

        return key, [key[0], key[1], key[2], key[1], key[3], key[1]]

    def get_ith_key192(self, key, round_i, number_of_operations, delta_constant, left_rotations_list):
        for operation in range(number_of_operations):
            delta_j = self.add_constant_component(self.WORD_SIZE, delta_constant)
            rot_j = self.add_rotate_component([delta_j.id], [get_ith_word(self.WORD_SIZE, 0)],
                                              self.WORD_SIZE, -(round_i + operation))
            mod_j = self.add_MODADD_component([key[operation].id] + [rot_j.id],
                                              key[operation].input_bit_positions + rot_j.input_bit_positions,
                                              self.WORD_SIZE)
            rot_c = self.add_rotate_component([mod_j.id], [get_ith_word(self.WORD_SIZE, 0)],
                                              self.WORD_SIZE, left_rotations_list[operation])
            key[operation] = rot_c

        return key, key

    def get_ith_key256(self, key, round_i, number_of_operations, delta_constant, left_rotations_list):
        for operation in range(number_of_operations):
            new_j = (6 * round_i + operation) % 8
            delta_j = self.add_constant_component(self.WORD_SIZE, delta_constant)
            rot_j = self.add_rotate_component([delta_j.id], [get_ith_word(self.WORD_SIZE, 0)],
                                              self.WORD_SIZE, -(round_i + operation))
            mod_j = self.add_MODADD_component([key[new_j].id] + [rot_j.id],
                                              key[new_j].input_bit_positions + rot_j.input_bit_positions,
                                              self.WORD_SIZE)
            rot_c = self.add_rotate_component([mod_j.id], [get_ith_word(self.WORD_SIZE, 0)],
                                              self.WORD_SIZE, left_rotations_list[operation])
            key[new_j] = rot_c

        key2 = []

        for i in range(6):
            key2.append(key[(6 * round_i + i) % 8])

        return key, key2

    def get_numbers_of_rounds(self, number_of_rounds):
        if number_of_rounds != 0:
            return number_of_rounds
        number_of_rounds = None
        for parameters in PARAMETERS_CONFIGURATION_LIST:
            if parameters['block_bit_size'] == self.block_bit_size and parameters['key_bit_size'] == self.key_bit_size:
                number_of_rounds = parameters['number_of_rounds']
                break

        if number_of_rounds is None:
            raise ValueError("No available number of rounds for the given parameters.")

        return number_of_rounds

    def round_function(self, internal_state, round_key):
        def word_function(i0, i1, i2, i3, rot_value):
            xor_w3_1 = self.add_XOR_component(
                [internal_state[i0].id] + [round_key[i1].id],
                internal_state[i0].input_bit_positions + round_key[i1].input_bit_positions,
                self.WORD_SIZE
            )
            xor_w1_2 = self.add_XOR_component(
                [internal_state[i2].id] + [round_key[i3].id],
                internal_state[i2].input_bit_positions + round_key[i3].input_bit_positions,
                self.WORD_SIZE
            )

            mod_1 = self.add_MODADD_component(
                [xor_w3_1.id] + [xor_w1_2.id],
                [get_ith_word(self.WORD_SIZE, 0)] + [get_ith_word(self.WORD_SIZE, 0)],
                self.WORD_SIZE,
            )

            rot_c = self.add_rotate_component(
                [mod_1.id],
                [get_ith_word(self.WORD_SIZE, 0)],
                self.WORD_SIZE,
                rot_value
            )

            return rot_c

        word_parameters = [
            [0, 0, 1, 1, -9],
            [1, 2, 2, 3, 5],
            [2, 4, 3, 5, 3]
        ]
        new_state = []

        for j in range(3):
            new_state.append(word_function(*word_parameters[j]))
        new_state.append(internal_state[0])

        return new_state
