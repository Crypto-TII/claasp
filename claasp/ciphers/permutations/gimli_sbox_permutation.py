
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
from claasp.utils.utils import simplify_inputs
from claasp.name_mappings import INPUT_PLAINTEXT
from claasp.DTOs.component_state import ComponentState

N_ROWS = 3
N_COLS = 4
NROUNDS = 24
SBOX_SIZE = N_ROWS
ROT_TABLE = [-24, -9]
GIMLI_SBOX = [0x0, 0x2, 0x0, 0x6, 0x2, 0x2, 0x3, 0x7]
PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 24, 'word_size': 32}]


def big_swap(states):
    temp = ComponentState(states[0][0].id, states[0][0].input_bit_positions)
    states[0][0] = ComponentState(states[0][2].id, states[0][2].input_bit_positions)
    states[0][2] = temp
    temp = ComponentState(states[0][1].id, states[0][1].input_bit_positions)
    states[0][1] = ComponentState(states[0][3].id, states[0][3].input_bit_positions)
    states[0][3] = temp

    return states


def small_swap(states):
    temp = ComponentState(states[0][0].id, states[0][0].input_bit_positions)
    states[0][0] = ComponentState(states[0][1].id, states[0][1].input_bit_positions)
    states[0][1] = temp
    temp = ComponentState(states[0][2].id, states[0][2].input_bit_positions)
    states[0][2] = ComponentState(states[0][3].id, states[0][3].input_bit_positions)
    states[0][3] = temp

    return states


class GimliSboxPermutation(Cipher):
    """
    Construct an instance of the GimliPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    This version considers the application of 32 parallel 3-bit S-boxes to each column.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `24`); number of rounds of the permutation
        - ``word_size`` -- **integer** (default: `32`); the size of the word

    EXAMPLES::

        sage: from claasp.ciphers.permutations.gimli_sbox_permutation import GimliSboxPermutation
        sage: gimli = GimliSboxPermutation(number_of_rounds=24, word_size=32)
        sage: gimli.number_of_rounds
        24

        sage: gimli.component_from(0, 0).id
        'rot_0_0'
    """

    def __init__(self, number_of_rounds=24, word_size=32):
        self.WORD_BIT_SIZE = word_size
        self.PLANE_SIZE = N_COLS * self.WORD_BIT_SIZE
        self.state_bit_size = N_ROWS * self.PLANE_SIZE

        super().__init__(family_name="gimli_sbox",
                         cipher_type="permutation",
                         cipher_inputs=[INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[self.state_bit_size],
                         cipher_output_bit_size=self.state_bit_size)

        # states initialization
        states = [[{} for _ in range(N_COLS)] for _ in range(N_ROWS)]
        for row in range(N_ROWS):
            for column in range(N_COLS):
                states[row][column] = ComponentState([INPUT_PLAINTEXT],
                                                     [[k + column * self.WORD_BIT_SIZE +
                                                       row * self.PLANE_SIZE for k in range(self.WORD_BIT_SIZE)]])

        # round function
        for round_number in range(number_of_rounds):
            self.add_round()
            states = self.round_function(states, 24 - round_number)

            # round output
            inputs_id = []
            inputs_pos = []
            for row in range(N_ROWS):
                for column in range(N_COLS):
                    inputs_id = inputs_id + states[row][column].id
                    inputs_pos = inputs_pos + states[row][column].input_bit_positions

            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def sp_box(self, states, current_round):
        # SP-box (Rotation)
        b = [[{} for _ in range(N_COLS)] for _ in range(N_ROWS)]
        for column_number in range(N_COLS):
            for row_number in range(N_ROWS - 1):
                self.add_rotate_component(states[row_number][column_number].id,
                                          states[row_number][column_number].input_bit_positions,
                                          self.WORD_BIT_SIZE, ROT_TABLE[row_number])
                b[row_number][column_number] = ComponentState([self.get_current_component_id()],
                                                              [list(range(self.WORD_BIT_SIZE))])
            b[2][column_number] = ComponentState(states[2][column_number].id,
                                                 states[2][column_number].input_bit_positions)

        # SP-box (T-function and swap)
        sp_states = [[{} for _ in range(N_COLS)] for _ in range(N_ROWS)]
        for column_number in range(N_COLS):
            # ------------------------------------------------------
            # x before substitution_layer-box
            self.add_SHIFT_component(
                b[2][column_number].id, b[2][column_number].input_bit_positions, self.WORD_BIT_SIZE, -1)
            b0_shift1 = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])
            inputs_id = b[0][column_number].id + b0_shift1.id
            inputs_pos = b[0][column_number].input_bit_positions + b0_shift1.input_bit_positions
            self.add_XOR_component(inputs_id, inputs_pos, self.WORD_BIT_SIZE)
            b0_xor = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])
            # ------------------------------------------------------
            # y before Sbox
            inputs_id = b[1][column_number].id + b[0][column_number].id
            inputs_pos = b[1][column_number].input_bit_positions + b[0][column_number].input_bit_positions
            self.add_XOR_component(inputs_id, inputs_pos, self.WORD_BIT_SIZE)
            b1_xor = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])

            # ------------------------------------------------------
            # z before Sbox
            inputs_id = b[2][column_number].id + b[1][column_number].id
            inputs_pos = b[2][column_number].input_bit_positions + b[1][column_number].input_bit_positions
            self.add_XOR_component(inputs_id, inputs_pos, self.WORD_BIT_SIZE)
            b2_xor = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])

            # ------------------------------------------------------
            # ------------------------------------------------------
            # Applying Sbox to x, y, z
            substitution_layer = []
            inputs_id = b[0][column_number].id + b[1][column_number].id + b[2][column_number].id
            for i in range(self.WORD_BIT_SIZE):
                if current_round == 24:
                    inputs_pos = [[i]] * (N_ROWS - 1) + \
                                 [[b[2][column_number].input_bit_positions[0][i % self.WORD_BIT_SIZE]]]
                else:
                    inputs_pos = [[i]] * N_ROWS
                self.add_SBOX_component(inputs_id, inputs_pos, N_ROWS, GIMLI_SBOX)
                substitution_layer.append(ComponentState([self.get_current_component_id()], [list(range(SBOX_SIZE))]))

            inputs_id = []
            for i in range(self.WORD_BIT_SIZE):
                inputs_id += substitution_layer[i].id
            lane_after_sb = [{} for _ in range(N_ROWS)]
            for i in range(N_ROWS):
                lane_after_sb[i] = ComponentState(inputs_id, [[i]] * self.WORD_BIT_SIZE)

            # ------------------------------------------------------
            # x after substitution_layer-box
            self.add_SHIFT_component(lane_after_sb[0].id, lane_after_sb[0].input_bit_positions, self.WORD_BIT_SIZE,
                                     -2)
            b0_shift2 = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])
            inputs_id = b0_xor.id + b0_shift2.id
            inputs_pos = b0_xor.input_bit_positions + b0_shift2.input_bit_positions
            self.add_XOR_component(inputs_id, inputs_pos, self.WORD_BIT_SIZE)

            # Swap x <- z
            sp_states[2][column_number] = ComponentState([self.get_current_component_id()],
                                                         [list(range(self.WORD_BIT_SIZE))])
            # ------------------------------------------------------
            # y after substitution_layer-box
            self.add_SHIFT_component(lane_after_sb[1].id, lane_after_sb[1].input_bit_positions, self.WORD_BIT_SIZE,
                                     -1)
            b1_shift = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])
            inputs_id = b1_xor.id + b1_shift.id
            inputs_pos = b1_xor.input_bit_positions + b1_shift.input_bit_positions
            self.add_XOR_component(inputs_id, inputs_pos, self.WORD_BIT_SIZE)

            sp_states[1][column_number] = ComponentState([self.get_current_component_id()],
                                                         [list(range(self.WORD_BIT_SIZE))])
            # ------------------------------------------------------
            # z after substitution_layer-box
            self.add_SHIFT_component(lane_after_sb[2].id, lane_after_sb[2].input_bit_positions, self.WORD_BIT_SIZE,
                                     -3)
            b2_shift = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])
            inputs_id = b2_xor.id + b2_shift.id
            inputs_pos = b2_xor.input_bit_positions + b2_shift.input_bit_positions
            self.add_XOR_component(inputs_id, inputs_pos, self.WORD_BIT_SIZE)

            # Swap z <- x
            sp_states[0][column_number] = ComponentState([self.get_current_component_id()],
                                                         [list(range(self.WORD_BIT_SIZE))])

        return sp_states

    def round_constant(self, states, rc):
        self.add_constant_component(self.WORD_BIT_SIZE, rc)
        c = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])
        # state[0,0] = state[0,0] xor RC
        inputs_id = c.id + states[0][0].id
        inputs_pos = c.input_bit_positions + states[0][0].input_bit_positions

        self.add_XOR_component(inputs_id, inputs_pos, self.WORD_BIT_SIZE)
        states[0][0] = ComponentState([self.get_current_component_id()], [list(range(self.WORD_BIT_SIZE))])

        return states

    def round_function(self, states, round):

        states = self.sp_box(states, round)

        inputs_id = []
        inputs_pos = []
        for row_number in range(N_ROWS):
            for column_number in range(N_COLS):
                inputs_id = inputs_id + states[row_number][column_number].id
                inputs_pos = inputs_pos + states[row_number][column_number].input_bit_positions

        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        self.add_intermediate_output_component(inputs_id, inputs_pos, self.state_bit_size, "round_output_nonlinear")

        if (round & 3) == 0:
            states = small_swap(states)

        if (round & 3) == 2:
            states = big_swap(states)

        if (round & 3) == 0:
            states = self.round_constant(states, 0x9E377900 ^ round)

        return states
