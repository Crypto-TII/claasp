
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
from claasp.utils.utils import get_ith_word
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

DELTA_CONSTANTS = [
    0x5a, 0x6d, 0x36, 0x1b, 0x0d, 0x06, 0x03, 0x41, 0x60, 0x30, 0x18, 0x4c, 0x66, 0x33, 0x59, 0x2c,
    0x56, 0x2b, 0x15, 0x4a, 0x65, 0x72, 0x39, 0x1c, 0x4e, 0x67, 0x73, 0x79, 0x3c, 0x5e, 0x6f, 0x37,
    0x5b, 0x2d, 0x16, 0x0b, 0x05, 0x42, 0x21, 0x50, 0x28, 0x54, 0x2a, 0x55, 0x6a, 0x75, 0x7a, 0x7d,
    0x3e, 0x5f, 0x2f, 0x17, 0x4b, 0x25, 0x52, 0x29, 0x14, 0x0a, 0x45, 0x62, 0x31, 0x58, 0x6c, 0x76,
    0x3b, 0x1d, 0x0e, 0x47, 0x63, 0x71, 0x78, 0x7c, 0x7e, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x43, 0x61,
    0x70, 0x38, 0x5c, 0x6e, 0x77, 0x7b, 0x3d, 0x1e, 0x4f, 0x27, 0x53, 0x69, 0x34, 0x1a, 0x4d, 0x26,
    0x13, 0x49, 0x24, 0x12, 0x09, 0x04, 0x02, 0x01, 0x40, 0x20, 0x10, 0x08, 0x44, 0x22, 0x11, 0x48,
    0x64, 0x32, 0x19, 0x0c, 0x46, 0x23, 0x51, 0x68, 0x74, 0x3a, 0x5d, 0x2e, 0x57, 0x6b, 0x35, 0x5a,
]
input_types = [INPUT_KEY, INPUT_PLAINTEXT]
PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 64, 'key_bit_size': 128, 'number_of_rounds': 32}]


def init_input(number_of_words, cipher_input, word_size):
    input_state = []
    for i in range(number_of_words):
        input_state_i = ComponentState(cipher_input, [get_ith_word(word_size, i, cipher_input, "")])
        input_state.append(input_state_i)

    return input_state


def temp_subkey_generation(master_key):
    master_key = master_key[::-1]
    secret_key = [0 for _ in range(128)]
    for i in range(8):
        for j in range(8):
            secret_key[16 * i + j] = {
                'delta_constant': DELTA_CONSTANTS[16 * i + j],
                'master_key': master_key[(j - i) % 8]
            }
            secret_key[16 * i + j + 8] = {
                'delta_constant': DELTA_CONSTANTS[16 * i + j + 8],
                'master_key': master_key[((j - i) % 8) + 8]
            }

    return secret_key


def whitening_key_generation(master_key):
    reverse_master_key = master_key[::-1]
    whitening_key_list = []
    for i in range(8):
        if 0 <= i <= 3:
            whitening_key_list.append(reverse_master_key[i + 12])
        else:
            whitening_key_list.append(reverse_master_key[i - 4])

    return whitening_key_list


class HightBlockCipher(Cipher):
    """
    Construct an instance of the HightBlockCipher class.

    This class is used to store compact representations of a cipher,
    used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``sub_keys_zero`` -- **boolean** (default: `False`)
    - ``transformations_flag`` -- **boolean** (default: `True`)

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.hight_block_cipher import HightBlockCipher
        sage: hight = HightBlockCipher(number_of_rounds=3)
        sage: hight.number_of_rounds
        3

        sage: hight.component_from(0, 0).id
        'modadd_0_0'
    """

    def __init__(self, block_bit_size=64, key_bit_size=128,
                 number_of_rounds=0, sub_keys_zero=False, transformations_flag=True):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.WORD_SIZE = 8

        super().__init__(family_name="hight",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        number_of_rounds = self.get_numbers_of_rounds(number_of_rounds)
        internal_state = init_input(8, INPUT_PLAINTEXT, self.WORD_SIZE)
        round_key_state = init_input(16, INPUT_KEY, self.WORD_SIZE)
        whitening_key_list = whitening_key_generation(round_key_state)
        round_key_state = temp_subkey_generation(round_key_state)
        for round_i in range(number_of_rounds):
            self.add_round()
            if round_i == 0 and transformations_flag:
                internal_state = self.initial_transformation(internal_state, whitening_key_list)
            round_key = self.create_sub_key(round_key_state[4 * round_i:4 * round_i + 4], sub_keys_zero)
            internal_state = self.round_function(internal_state, round_key)
            if round_i == number_of_rounds - 1 and transformations_flag:
                internal_state = self.final_transformation(internal_state, whitening_key_list)
            self.add_intermediate_output_components(round_key, internal_state, number_of_rounds, round_i)

    def add_intermediate_output_components(self, round_key, internal_state, number_of_rounds, round_i):
        self.add_round_key_output_component(
            [round_key[k].id for k in range(4)],
            [get_ith_word(self.WORD_SIZE, 0, round_key[k].id, round_key[k].input_bit_positions) for k in
             range(4)],
            4 * self.WORD_SIZE
        )
        first_input_bit_positions = []
        for k in range(8):
            if internal_state[k].id in input_types and round_i == 0:
                first_input_bit_positions.append(internal_state[k].input_bit_positions[0])
            else:
                first_input_bit_positions.append(get_ith_word(self.WORD_SIZE, 0, "", ""))

        if round_i == number_of_rounds - 1:
            self.add_cipher_output_component([internal_state[k].id for k in range(8)],
                                             first_input_bit_positions,
                                             self.block_bit_size)
        else:
            self.add_round_output_component([internal_state[k].id for k in range(8)],
                                            first_input_bit_positions,
                                            self.block_bit_size)

    def create_sub_key(self, sub_key_temp_list, sub_keys_zero):
        if sub_keys_zero:
            return [
                sub_key_temp_list[0]['master_key'],
                sub_key_temp_list[1]['master_key'],
                sub_key_temp_list[2]['master_key'],
                sub_key_temp_list[1]['master_key']
            ]

        sub_key_lst = []
        for sub_key_temp in sub_key_temp_list:
            delta = self.add_constant_component(8, sub_key_temp['delta_constant'])

            mod_a = self.add_MODADD_component(
                [sub_key_temp['master_key'].id] + [delta.id],
                sub_key_temp['master_key'].input_bit_positions + [list(range(8))],
                8,
            )
            sub_key_lst.append(mod_a)

        return sub_key_lst

    def final_transformation(self, plaintext_list, whitening_key_list):
        def temp_final_transformation(a, b, c, d):
            mod_temp_1 = self.add_MODADD_component([plaintext_list[a].id] + [whitening_key_list[b].id],
                                                   [list(range(8))] + whitening_key_list[b].input_bit_positions,
                                                   8)
            xor_temp_1 = self.add_XOR_component([plaintext_list[c].id] + [whitening_key_list[d].id],
                                                [list(range(8))] + whitening_key_list[d].input_bit_positions,
                                                8)
            return mod_temp_1, xor_temp_1

        plaintext_list = plaintext_list[::-1]

        mod_1, xor_1 = temp_final_transformation(1, 4, 3, 5)
        mod_2, xor_2 = temp_final_transformation(5, 6, 7, 7)
        final_transformation_result = [mod_1, plaintext_list[2], xor_1, plaintext_list[4],
                                       mod_2, plaintext_list[6], xor_2, plaintext_list[0]]

        return final_transformation_result[::-1]

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

    def initial_transformation(self, plaintext_list, whitening_key_list):
        def temp_initial_transformation(a, b, c, d):
            mod_temp_1 = self.add_MODADD_component(
                [plaintext_list[a].id] + [whitening_key_list[b].id],
                plaintext_list[a].input_bit_positions + whitening_key_list[b].input_bit_positions,
                8)
            xor_temp_1 = self.add_XOR_component(
                [plaintext_list[c].id] + [whitening_key_list[d].id],
                plaintext_list[c].input_bit_positions + whitening_key_list[d].input_bit_positions,
                8)

            return mod_temp_1, xor_temp_1

        plaintext_list = plaintext_list[::-1]
        mod_1, xor_1 = temp_initial_transformation(0, 0, 2, 1)
        mod_2, xor_2 = temp_initial_transformation(4, 2, 6, 3)
        initial_transformation_result = [
            mod_1, plaintext_list[1], xor_1, plaintext_list[3],
            mod_2, plaintext_list[5], xor_2, plaintext_list[7]
        ]

        return initial_transformation_result[::-1]

    def round_function(self, internal_state, round_key):
        def f0(x):
            rot_1 = self.add_rotate_component([x.id],
                                              [get_ith_word(self.WORD_SIZE, 0, x.id, x.input_bit_positions)],
                                              self.WORD_SIZE,
                                              -1)

            rot_2 = self.add_rotate_component([x.id],
                                              [get_ith_word(self.WORD_SIZE, 0, x.id, x.input_bit_positions)],
                                              self.WORD_SIZE,
                                              -2)

            rot_7 = self.add_rotate_component([x.id],
                                              [get_ith_word(self.WORD_SIZE, 0, x.id, x.input_bit_positions)],
                                              self.WORD_SIZE,
                                              -7)

            xor_1 = self.add_XOR_component(
                [rot_1.id] + [rot_2.id],
                [get_ith_word(self.WORD_SIZE, 0, rot_1.id, rot_1.input_bit_positions)] +
                [get_ith_word(self.WORD_SIZE, 0, rot_2.id, rot_2.input_bit_positions)],
                self.WORD_SIZE)

            xor_2 = self.add_XOR_component(
                [xor_1.id] + [rot_7.id],
                [get_ith_word(self.WORD_SIZE, 0, xor_1.id, xor_1.input_bit_positions)] +
                [get_ith_word(self.WORD_SIZE, 0, rot_7.id, rot_7.input_bit_positions)],
                self.WORD_SIZE)

            return xor_2

        def f1(x):
            rot_1 = self.add_rotate_component([x.id],
                                              [get_ith_word(self.WORD_SIZE, 0, x.id, x.input_bit_positions)],
                                              self.WORD_SIZE,
                                              -3)

            rot_2 = self.add_rotate_component([x.id],
                                              [get_ith_word(self.WORD_SIZE, 0, x.id, x.input_bit_positions)],
                                              self.WORD_SIZE,
                                              -4)

            rot_7 = self.add_rotate_component([x.id],
                                              [get_ith_word(self.WORD_SIZE, 0, x.id, x.input_bit_positions)],
                                              self.WORD_SIZE,
                                              -6)

            xor_1 = self.add_XOR_component(
                [rot_1.id] + [rot_2.id],
                [get_ith_word(self.WORD_SIZE, 0, rot_1.id, rot_1.input_bit_positions)] +
                [get_ith_word(self.WORD_SIZE, 0, rot_2.id, rot_2.input_bit_positions)],
                self.WORD_SIZE)

            xor_2 = self.add_XOR_component(
                [xor_1.id] + [rot_7.id],
                [get_ith_word(self.WORD_SIZE, 0, xor_1.id, xor_1.input_bit_positions)] +
                [get_ith_word(self.WORD_SIZE, 0, rot_7.id, rot_7.input_bit_positions)],
                self.WORD_SIZE)

            return xor_2

        def f3_xor(x1, x2, x3, f):
            x2p = f(x2)
            mod_1 = self.add_MODADD_component([x2p.id] + [x3.id],
                                              [get_ith_word(self.WORD_SIZE, 0, x2p.id, x2p.input_bit_positions)] +
                                              [get_ith_word(self.WORD_SIZE, 0, x3.id, x3.input_bit_positions)],
                                              self.WORD_SIZE)

            xor_1 = self.add_XOR_component([x1.id] + [mod_1.id],
                                           [get_ith_word(self.WORD_SIZE, 0, x1.id, x1.input_bit_positions)] +
                                           [get_ith_word(self.WORD_SIZE, 0, mod_1.id, mod_1.input_bit_positions)],
                                           self.WORD_SIZE)

            return xor_1

        def f3_mod(x1, x2, x3, f):
            x2p = f(x2)
            xor_1 = self.add_XOR_component([x2p.id] + [x3.id],
                                           [get_ith_word(self.WORD_SIZE, 0, x2p.id, x2p.input_bit_positions)] +
                                           [get_ith_word(self.WORD_SIZE, 0, x3.id, x3.input_bit_positions)],
                                           self.WORD_SIZE)

            mod_1 = self.add_MODADD_component(
                [x1.id] + [xor_1.id],
                [get_ith_word(self.WORD_SIZE, 0, x1.id, x1.input_bit_positions)] +
                [get_ith_word(self.WORD_SIZE, 0, xor_1.id, xor_1.input_bit_positions)],
                self.WORD_SIZE)

            return mod_1

        new_state = [None for _ in range(self.WORD_SIZE)]
        new_state[0] = internal_state[1]
        new_state[1] = f3_mod(internal_state[2], internal_state[3], round_key[2], f1)
        new_state[2] = internal_state[3]

        new_state[3] = f3_xor(internal_state[4], internal_state[5], round_key[1], f0)
        new_state[4] = internal_state[5]
        new_state[5] = f3_mod(internal_state[6], internal_state[7], round_key[0], f1)
        new_state[6] = internal_state[7]
        new_state[7] = f3_xor(internal_state[0], internal_state[1], round_key[3], f0)

        return new_state
