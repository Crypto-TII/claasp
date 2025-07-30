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
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY
from claasp.utils.utils import get_inputs_parameter


PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64, "key_bit_size": 64, "number_of_rounds": 32},
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 36},
    {"block_bit_size": 64, "key_bit_size": 192, "number_of_rounds": 40},
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 40},
    {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 48},
    {"block_bit_size": 128, "key_bit_size": 384, "number_of_rounds": 56},
]

# fmt: off
MIX_COLUMN_MATRIX = [
    [1, 0, 1, 1],
    [1, 0, 0, 0],
    [0, 1, 1, 0],
    [1, 0, 1, 0],
]
ROUND_CONSTANTS_0 = [
    0x1, 0x3, 0x7, 0xF, 0xF, 0xE, 0xD, 0xB, 0x7, 0xF, 0xE, 0xC, 0x9, 0x3, 0x7, 0xE,
    0xD, 0xA, 0x5, 0xB, 0x6, 0xC, 0x8, 0x0, 0x1, 0x2, 0x5, 0xB, 0x7, 0xE, 0xC, 0x8,
    0x1, 0x3, 0x6, 0xD, 0xB, 0x6, 0xD, 0xA, 0x4, 0x9, 0x2, 0x4, 0x8, 0x1, 0x2, 0x4,
    0x9, 0x3, 0x6, 0xC, 0x9, 0x2, 0x5, 0xA, 0x5, 0xA, 0x4, 0x8, 0x0, 0x0

]
ROUND_CONSTANTS_1 = [
    0x0, 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, 0x3, 0x3, 0x2, 0x1, 0x3, 0x3, 0x3, 0x2, 0x0,
    0x1, 0x3, 0x3, 0x2, 0x1, 0x2, 0x1, 0x3, 0x2, 0x0, 0x0, 0x0, 0x1, 0x2, 0x1, 0x3,
    0x3, 0x2, 0x0, 0x0, 0x1, 0x3, 0x2, 0x1, 0x3, 0x2, 0x1, 0x2, 0x0, 0x1, 0x2, 0x0,
    0x0, 0x1, 0x2, 0x0, 0x1, 0x3, 0x2, 0x0, 0x1, 0x2, 0x1, 0x2, 0x1, 0x2

]
ROUND_CONSTANT_2 = 0x2
S_BOX_4_BITS = [0xC, 0x6, 0x9, 0x0, 0x1, 0xA, 0x2, 0xB, 0x3, 0x8, 0x5, 0xD, 0x4, 0xE, 0x7, 0xF]
S_BOX_8_BITS = [
    0x65, 0x4C, 0x6A, 0x42, 0x4B, 0x63, 0x43, 0x6B, 0x55, 0x75, 0x5A, 0x7A, 0x53, 0x73, 0x5B, 0x7B,
    0x35, 0x8C, 0x3A, 0x81, 0x89, 0x33, 0x80, 0x3B, 0x95, 0x25, 0x98, 0x2A, 0x90, 0x23, 0x99, 0x2B,
    0xE5, 0xCC, 0xE8, 0xC1, 0xC9, 0xE0, 0xC0, 0xE9, 0xD5, 0xF5, 0xD8, 0xF8, 0xD0, 0xF0, 0xD9, 0xF9,
    0xA5, 0x1C, 0xA8, 0x12, 0x1B, 0xA0, 0x13, 0xA9, 0x05, 0xB5, 0x0A, 0xB8, 0x03, 0xB0, 0x0B, 0xB9,
    0x32, 0x88, 0x3C, 0x85, 0x8D, 0x34, 0x84, 0x3D, 0x91, 0x22, 0x9C, 0x2C, 0x94, 0x24, 0x9D, 0x2D,
    0x62, 0x4A, 0x6C, 0x45, 0x4D, 0x64, 0x44, 0x6D, 0x52, 0x72, 0x5C, 0x7C, 0x54, 0x74, 0x5D, 0x7D,
    0xA1, 0x1A, 0xAC, 0x15, 0x1D, 0xA4, 0x14, 0xAD, 0x02, 0xB1, 0x0C, 0xBC, 0x04, 0xB4, 0x0D, 0xBD,
    0xE1, 0xC8, 0xEC, 0xC5, 0xCD, 0xE4, 0xC4, 0xED, 0xD1, 0xF1, 0xDC, 0xFC, 0xD4, 0xF4, 0xDD, 0xFD,
    0x36, 0x8E, 0x38, 0x82, 0x8B, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9A, 0x28, 0x93, 0x20, 0x9B, 0x29,
    0x66, 0x4E, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
    0xA6, 0x1E, 0xAA, 0x11, 0x19, 0xA3, 0x10, 0xAB, 0x06, 0xB6, 0x08, 0xBA, 0x00, 0xB3, 0x09, 0xBB,
    0xE6, 0xCE, 0xEA, 0xC2, 0xCB, 0xE3, 0xC3, 0xEB, 0xD6, 0xF6, 0xDA, 0xFA, 0xD3, 0xF3, 0xDB, 0xFB,
    0x31, 0x8A, 0x3E, 0x86, 0x8F, 0x37, 0x87, 0x3F, 0x92, 0x21, 0x9E, 0x2E, 0x97, 0x27, 0x9F, 0x2F,
    0x61, 0x48, 0x6E, 0x46, 0x4F, 0x67, 0x47, 0x6F, 0x51, 0x71, 0x5E, 0x7E, 0x57, 0x77, 0x5F, 0x7F,
    0xA2, 0x18, 0xAE, 0x16, 0x1F, 0xA7, 0x17, 0xAF, 0x01, 0xB2, 0x0E, 0xBE, 0x07, 0xB7, 0x0F, 0xBF,
    0xE2, 0xCA, 0xEE, 0xC6, 0xCF, 0xE7, 0xC7, 0xEF, 0xD2, 0xF2, 0xDE, 0xFE, 0xD7, 0xF7, 0xDF, 0xFF,
]
NUMBER_OF_ROWS = 4
NUMBER_OF_COLUMNS = 4
NUMBER_OF_CELLS = NUMBER_OF_ROWS * NUMBER_OF_COLUMNS
LFSR_TK2_4BITS = [[0, 0, 0, 1], [1, 0, 0, 1], [0, 1, 0, 0], [0, 0, 1, 0]]
LFSR_TK3_4BITS = [[1, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [1, 0, 0, 0]]
LFSR_TK2_8BITS = [
    [0, 0, 0, 0, 0, 0, 0, 1],
    [1, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 1],
    [0, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0],
]
LFSR_TK3_8BITS = [
    [0, 1, 0, 0, 0, 0, 0, 0],
    [1, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0, 0, 1],
    [1, 0, 0, 0, 0, 0, 0, 0],
]
# fmt: on


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

    def __init__(self, block_bit_size=64, key_bit_size=64, number_of_rounds=32):
        super().__init__(
            family_name="skinny",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        self.block_bit_size = block_bit_size
        self.cell_size = block_bit_size // 16
        self.number_of_key_arrays = key_bit_size // block_bit_size

        # choose the S-box
        if self.cell_size == 4:
            self.sbox = S_BOX_4_BITS
            self.lfsr_tk2 = LFSR_TK2_4BITS
            self.lfsr_tk3 = LFSR_TK3_4BITS
        elif self.cell_size == 8:
            self.sbox = S_BOX_8_BITS
            self.lfsr_tk2 = LFSR_TK2_8BITS
            self.lfsr_tk3 = LFSR_TK3_8BITS

        # state and key initialization
        state = self.state_initialization()
        key = self.key_initialization()

        self.add_round()
        self.add_constant_component(self.cell_size, ROUND_CONSTANT_2)
        rc2 = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])

        for round_number in range(number_of_rounds - 1):
            state = self.round_function(state, key, round_number, rc2)
            inputs_id, inputs_pos = get_inputs_parameter(state)
            self.add_round_output_component(inputs_id, inputs_pos, block_bit_size)
            key = self.key_schedule(key)
            inputs_id, inputs_pos = get_inputs_parameter([key_state for key_array in key for key_state in key_array])
            self.add_round_key_output_component(inputs_id, inputs_pos, key_bit_size)
            self.add_round()
        state = self.round_function(state, key, number_of_rounds - 1, rc2)
        inputs_id, inputs_pos = get_inputs_parameter(state)
        self.add_cipher_output_component(inputs_id, inputs_pos, block_bit_size)

    def state_initialization(self):
        state = []
        for cell_number in range(NUMBER_OF_CELLS):
            input_bit_positions = [i + cell_number * self.cell_size for i in range(self.cell_size)]
            component_state = ComponentState([INPUT_PLAINTEXT], [input_bit_positions])
            state.append(component_state)

        return state

    def key_initialization(self):
        key = [[] for _ in range(self.number_of_key_arrays)]
        for key_arrays_number in range(self.number_of_key_arrays):
            for cell_number in range(NUMBER_OF_CELLS):
                input_bit_positions = [
                    i + cell_number * self.cell_size + key_arrays_number * self.block_bit_size
                    for i in range(self.cell_size)
                ]
                component_state = ComponentState([INPUT_KEY], [input_bit_positions])
                key[key_arrays_number].append(component_state)

        return key

    def round_function(self, state, key, round_number, rc2):
        # SubCells
        for cell_number in range(NUMBER_OF_CELLS):
            self.add_SBOX_component(
                state[cell_number].id, state[cell_number].input_bit_positions, self.cell_size, self.sbox
            )
            state[cell_number] = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])

        # AddConstants c0
        self.add_constant_component(self.cell_size, ROUND_CONSTANTS_0[round_number])
        rc0 = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])
        inputs_id, inputs_positions = get_inputs_parameter([state[0], rc0])
        self.add_XOR_component(inputs_id, inputs_positions, self.cell_size)
        state[0] = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])

        # AddConstants c1
        self.add_constant_component(self.cell_size, ROUND_CONSTANTS_1[round_number])
        rc1 = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])
        inputs_id, inputs_pos = get_inputs_parameter([state[4], rc1])
        self.add_XOR_component(inputs_id, inputs_pos, self.cell_size)
        state[4] = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])

        # AddConstants c2
        inputs_id, inputs_pos = get_inputs_parameter([state[8], rc2])
        self.add_XOR_component(inputs_id, inputs_pos, self.cell_size)
        state[8] = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])

        # AddRoundTweakey
        for key_arrays_number in range(self.number_of_key_arrays):
            for cell_number in range(2 * NUMBER_OF_ROWS):
                inputs_id, inputs_pos = get_inputs_parameter([state[cell_number], key[key_arrays_number][cell_number]])
                self.add_XOR_component(inputs_id, inputs_pos, self.cell_size)
                state[cell_number] = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])

        # ShiftRows
        state[4], state[5], state[6], state[7] = state[7], state[4], state[5], state[6]
        state[8], state[9], state[10], state[11] = state[10], state[11], state[8], state[9]
        state[12], state[13], state[14], state[15] = state[13], state[14], state[15], state[12]

        # MixColumns
        mix_column_state = []
        for i in range(4):
            inputs_id, inputs_pos = get_inputs_parameter([state[i], state[i + 8], state[i + 12]])
            self.add_XOR_component(inputs_id, inputs_pos, self.cell_size)
            mix_column_state.append(ComponentState([self.get_current_component_id()], [list(range(self.cell_size))]))
        for i in range(4):
            mix_column_state.append(state[i])
        for i in range(4):
            inputs_id, inputs_pos = get_inputs_parameter([state[i + 4], state[i + 8]])
            self.add_XOR_component(inputs_id, inputs_pos, self.cell_size)
            mix_column_state.append(ComponentState([self.get_current_component_id()], [list(range(self.cell_size))]))
        for i in range(4):
            inputs_id, inputs_pos = get_inputs_parameter([state[i], state[i + 8]])
            self.add_XOR_component(inputs_id, inputs_pos, self.cell_size)
            mix_column_state.append(ComponentState([self.get_current_component_id()], [list(range(self.cell_size))]))

        return mix_column_state

    def key_schedule(self, key):
        for i in range(self.number_of_key_arrays):
            # fmt: off
            (
                key[i][0], key[i][1], key[i][2], key[i][3],
                key[i][4], key[i][5], key[i][6], key[i][7],
                key[i][8], key[i][9], key[i][10], key[i][11],
                key[i][12], key[i][13], key[i][14], key[i][15],
            ) = (
                key[i][9], key[i][15], key[i][8], key[i][13],
                key[i][10], key[i][14], key[i][12], key[i][11],
                key[i][0], key[i][1], key[i][2], key[i][3],
                key[i][4], key[i][5], key[i][6], key[i][7],
            )
            # fmt: on

        if self.number_of_key_arrays > 1:
            for cell_number in range(2 * NUMBER_OF_COLUMNS):
                input_id, input_pos = get_inputs_parameter([key[1][cell_number]])
                self.add_linear_layer_component(input_id, input_pos, self.cell_size, self.lfsr_tk2)
                key[1][cell_number] = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])

        if self.number_of_key_arrays > 2:
            for cell_number in range(2 * NUMBER_OF_COLUMNS):
                input_id, input_pos = get_inputs_parameter([key[2][cell_number]])
                self.add_linear_layer_component(input_id, input_pos, self.cell_size, self.lfsr_tk3)
                key[2][cell_number] = ComponentState([self.get_current_component_id()], [list(range(self.cell_size))])

        return key
