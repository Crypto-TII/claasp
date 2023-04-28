
# ****************************************************************************
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


from copy import deepcopy

from claasp.cipher import Cipher
from claasp.utils.utils import get_inputs_parameter
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

# NIST LW cipher parameters
PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 128, 'key_bit_size': 384, 'number_of_rounds': 40}]
CELL_SIZE = 8
ROW = 4
COLUMN = 4
STATE_LEN = ROW * COLUMN
KEY_LEN = ROW * COLUMN
S_BOX = [0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
         0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
         0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
         0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
         0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
         0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
         0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
         0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
         0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
         0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
         0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
         0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
         0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
         0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
         0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
         0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff]
M = [[1, 0, 1, 1],
     [1, 0, 0, 0],
     [0, 1, 1, 0],
     [1, 0, 1, 0]]
IRREDUCIBLE_POLYNOMIAL = 0x11d
ROUND_CONSTANT_0 = [0x1, 0x3, 0x7, 0xF, 0xF, 0xE, 0xD, 0xB, 0x7, 0xF, 0xE, 0xC, 0x9, 0x3, 0x7, 0xE,
                    0xD, 0xA, 0x5, 0xB, 0x6, 0xC, 0x8, 0x0, 0x1, 0x2, 0x5, 0xB, 0x7, 0xE, 0xC, 0x8,
                    0x1, 0x3, 0x6, 0xD, 0xB, 0x6, 0xD, 0xA]
ROUND_CONSTANT_1 = [0x0, 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, 0x3, 0x3, 0x2, 0x1, 0x3, 0x3, 0x3, 0x2, 0x0,
                    0x1, 0x3, 0x3, 0x2, 0x1, 0x2, 0x1, 0x3, 0x2, 0x0, 0x0, 0x0, 0x1, 0x2, 0x1, 0x3,
                    0x3, 0x2, 0x0, 0x0, 0x1, 0x3, 0x2, 0x1]
ROUND_CONSTANT_2 = 0x2


def add_shift_rows_components(state):
    # # state_new[i,j] = state[i, (j+i)%4) for i,j in range(4)
    state_new = []
    for row in range(ROW):
        for column in range(COLUMN):
            state_new.append(state[row * COLUMN + ((column - row) % COLUMN)])
    state = deepcopy(state_new)

    return state


def key_initialization():
    key = []
    for i in range(KEY_LEN * 3):
        p = ComponentState([INPUT_KEY], [[k + i * CELL_SIZE for k in range(CELL_SIZE)]])
        key.append(p)

    return key


def state_initialization():
    state = []
    for i in range(STATE_LEN):
        input_bit_positions = [k + i * CELL_SIZE for k in range(CELL_SIZE)]
        p = ComponentState([INPUT_PLAINTEXT], [input_bit_positions])
        state.append(p)

    return state


class SkinnyBlockCipher(Cipher):
    """
    Construct an instance of the SkinnyBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `384`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `40`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
        sage: skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=384, number_of_rounds=40)
        sage: skinny.number_of_rounds
        40

        sage: skinny.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, block_bit_size=128, key_bit_size=384, number_of_rounds=40):
        super().__init__(family_name='skinny',
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[block_bit_size, key_bit_size],
                         cipher_output_bit_size=block_bit_size)

        state = state_initialization()
        key = key_initialization()

        self.add_round()
        const_0, rc_2 = self.initial_round_elements_definition()

        for round_number in range(number_of_rounds):
            state = self.round_function(state, key, round_number, rc_2)

            inputs = []
            for i in range(KEY_LEN * 3):
                inputs.append(key[i])
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_round_key_output_component(inputs_id, inputs_pos, key_bit_size)

            key = self.add_output_component(block_bit_size, const_0, key, number_of_rounds, round_number, state)

    def add_add_round_tweakey(self, key, state):
        # # state[i] = state[i] key1[i] xor key[16+i] xor key[32+i] for  0 <= i < 8
        for i in range(2 * ROW):
            inputs_id, inputs_pos = get_inputs_parameter(
                [state[i], key[i], key[i + KEY_LEN], key[i + KEY_LEN * 2]])
            self.add_XOR_component(inputs_id, inputs_pos, CELL_SIZE)
            state[i] = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])

    def add_mix_column_serials(self, state):
        # state = M x state
        for column in range(COLUMN):
            inputs_id, inputs_pos = get_inputs_parameter([state[column + row * ROW] for row in range(ROW)])
            self.add_mix_column_component(inputs_id, inputs_pos, CELL_SIZE * COLUMN,
                                          [M, IRREDUCIBLE_POLYNOMIAL, CELL_SIZE])
            for row in range(ROW):
                state[column + row * ROW] = ComponentState([self.get_current_component_id()],
                                                           [[k + row * CELL_SIZE for k in range(CELL_SIZE)]])

        return state

    def add_output_component(self, block_bit_size, const_0, key, number_of_rounds, round_number, state):
        inputs = []
        for i in range(STATE_LEN):
            inputs.append(state[i])
        inputs_id, inputs_pos = get_inputs_parameter(inputs)
        if round_number == number_of_rounds - 1:
            self.add_cipher_output_component(inputs_id, inputs_pos, block_bit_size)
        else:
            self.add_round_output_component(inputs_id, inputs_pos, block_bit_size)
            # next round initialization
            self.add_round()
            # key schedule
            key = self.key_schedule(key, const_0)

        return key

    def initial_round_elements_definition(self):
        # constant 0 with 7 bits
        self.add_constant_component(CELL_SIZE, 0)
        const_0 = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE - 1))])
        # round constant c2
        self.add_constant_component(CELL_SIZE, ROUND_CONSTANT_2)
        rc_2 = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])

        return const_0, rc_2

    def key_schedule(self, key, const_0):
        # Keyi = Permutation(Keyi)
        # Permutation = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]
        new_key = []
        for i in range(3):
            new_key.append(key[9 + i * KEY_LEN])
            new_key.append(key[15 + i * KEY_LEN])
            new_key.append(key[8 + i * KEY_LEN])
            new_key.append(key[13 + i * KEY_LEN])
            new_key.append(key[10 + i * KEY_LEN])
            new_key.append(key[14 + i * KEY_LEN])
            new_key.append(key[12 + i * KEY_LEN])
            new_key.append(key[11 + i * KEY_LEN])
            new_key.append(key[0 + i * KEY_LEN])
            new_key.append(key[1 + i * KEY_LEN])
            new_key.append(key[2 + i * KEY_LEN])
            new_key.append(key[3 + i * KEY_LEN])
            new_key.append(key[4 + i * KEY_LEN])
            new_key.append(key[5 + i * KEY_LEN])
            new_key.append(key[6 + i * KEY_LEN])
            new_key.append(key[7 + i * KEY_LEN])
        key = deepcopy(new_key)

        # # Key1 = LFSR(Key1) for first 8 cells
        # # x7||x6||x5||x4||x3||x2||x1||x0 -> x6||x5||x4||x3||x2||x1||x0||x7 xor x5
        for i in range(2 * ROW):
            self.add_rotate_component(key[i + KEY_LEN].id, key[i + KEY_LEN].input_bit_positions, CELL_SIZE, -1)
            temp_rotate = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])
            self.add_XOR_component(temp_rotate.id + const_0.id + key[i + KEY_LEN].id,
                                   temp_rotate.input_bit_positions + const_0.input_bit_positions +
                                   [[key[i + KEY_LEN].input_bit_positions[0][2]]],
                                   CELL_SIZE)
            key[i + KEY_LEN] = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])

        # # Key2 = LFSR(Key2) for first 8 cells
        # # x7||x6||x5||x4||x3||x2||x1||x0 -> x0 xor x6||x7||x6||x5||x4||x3||x2||x1
        for i in range(2 * ROW):
            self.add_rotate_component(key[i + 2 * KEY_LEN].id, key[i + 2 * KEY_LEN].input_bit_positions, CELL_SIZE, 1)
            temp_rotate = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])
            self.add_XOR_component(temp_rotate.id + key[i + 2 * KEY_LEN].id + const_0.id,
                                   temp_rotate.input_bit_positions +
                                   [[key[i + 2 * KEY_LEN].input_bit_positions[0][1]]] + const_0.input_bit_positions,
                                   CELL_SIZE)
            key[i + 2 * KEY_LEN] = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])

        return key

    def round_function(self, state, key, r, rc_2):
        # SubCells
        # state[i, j] = s_box(state[i, j])
        for i in range(STATE_LEN):
            self.add_SBOX_component(state[i].id, state[i].input_bit_positions, CELL_SIZE, S_BOX)
            state[i] = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])

        # state[0,0] = state[0,0] xor rc_0
        self.add_constant_component(CELL_SIZE, ROUND_CONSTANT_0[r])
        rc_0 = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[0], rc_0])
        self.add_XOR_component(inputs_id, inputs_pos, CELL_SIZE)
        state[0] = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])

        # state[1,0] = state[1,0] xor rc_1
        self.add_constant_component(CELL_SIZE, ROUND_CONSTANT_1[r])
        rc_1 = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[4], rc_1])
        self.add_XOR_component(inputs_id, inputs_pos, CELL_SIZE)
        state[4] = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])

        # state[2,0] = state[2,0] xor rc_2
        inputs_id, inputs_pos = get_inputs_parameter([state[8], rc_2])
        self.add_XOR_component(inputs_id, inputs_pos, CELL_SIZE)
        state[8] = ComponentState([self.get_current_component_id()], [list(range(CELL_SIZE))])

        self.add_add_round_tweakey(key, state)
        state = add_shift_rows_components(state)

        return self.add_mix_column_serials(state)
