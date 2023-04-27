
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


from copy import deepcopy

from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_PLAINTEXT
from claasp.utils.utils import get_inputs_parameter
from claasp.DTOs.component_state import ComponentState

WORD_SIZE = 32
AZ_ROTATE = [(31, 24),
             (17, 17),
             (0, 31),
             (24, 16)]
CI = [0xB7E15162, 0xBF715880,
      0x38B4DA56, 0x324E7738,
      0xBB1185EB, 0x4F7C7B57,
      0xCFBFA1C8, 0xC2B3293D]
PARAMETERS_CONFIGURATION_LIST = [
    {'number_of_blocks': 4, 'number_of_steps': 7},
    {'number_of_blocks': 4, 'number_of_steps': 10},
    {'number_of_blocks': 6, 'number_of_steps': 7},
    {'number_of_blocks': 6, 'number_of_steps': 11},
    {'number_of_blocks': 8, 'number_of_steps': 8},
    {'number_of_blocks': 8, 'number_of_steps': 12},
]


class SparklePermutation(Cipher):
    """
    Construct an instance of the SparklePermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``number_of_blocks`` -- **integer** (default: `4`); block size // 64
    - ``number_of_steps`` -- **integer** (default: `7`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.sparkle_permutation import SparklePermutation
        sage: sparkle = SparklePermutation()
        sage: sparkle.number_of_rounds
        7

        sage: sparkle.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, number_of_blocks=4, number_of_steps=7):
        self.state_bit_size = WORD_SIZE * number_of_blocks * 2

        super().__init__(family_name="sparkle",
                         cipher_type="permutation",
                         cipher_inputs=[INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[self.state_bit_size],
                         cipher_output_bit_size=self.state_bit_size)

        self.add_round()

        # state initialization
        state = []
        for i in range(2 * number_of_blocks):
            state.append(ComponentState([INPUT_PLAINTEXT], [[k + i * WORD_SIZE for k in range(WORD_SIZE)]]))

        # assign constants
        constant_ci = []
        for i in range(8):
            self.add_constant_component(WORD_SIZE, CI[i])
            constant_ci.append(ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]))

        constant_r = []
        for i in range(number_of_steps):
            self.add_constant_component(WORD_SIZE, i)
            constant_r.append(ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]))

        for r in range(number_of_steps):
            # round function
            state = self.round_function(state, constant_ci, constant_r[r], r)

            # round output
            inputs = []
            for i in range(len(state)):
                inputs.append(deepcopy(state[i]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            if r == number_of_steps - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)
                # initial next round element
                self.add_round()

    def alzette(self, state_x, state_y, ci):
        for i in range(4):
            state_x, state_y = self.alzette_round(state_x, state_y, AZ_ROTATE[i][1], AZ_ROTATE[i][0], ci)

        return state_x, state_y

    def alzette_round(self, state_x, state_y, rotate_x, rotate_y, ci):
        # x = x + (y >> rotate_y)
        self.add_rotate_component(state_y.id, state_y.input_bit_positions, WORD_SIZE, rotate_y)
        temp = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state_x, temp])
        self.add_MODADD_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # y = y xor (x >> rotate_x)
        self.add_rotate_component(state_x.id, state_x.input_bit_positions, WORD_SIZE, rotate_x)
        temp = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state_y, temp])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # x = x xor ci
        inputs_id, inputs_pos = get_inputs_parameter([state_x, ci])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state_x, state_y

    def ell_function(self, state_i):
        # lx = (x <<< 16) xor (x and 0xffff)
        state_left = ComponentState(state_i.id, [[state_i.input_bit_positions[0][k] for k in range(WORD_SIZE // 2)]])
        state_right = ComponentState(state_i.id,
                                     [[state_i.input_bit_positions[0][k] for k in range(WORD_SIZE // 2, WORD_SIZE)]])
        inputs_id, inputs_pos = get_inputs_parameter([state_left, state_right])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE // 2)
        state_left = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE // 2))])

        inputs_id, inputs_pos = get_inputs_parameter([state_left, state_right])
        self.add_rotate_component(inputs_id, inputs_pos, WORD_SIZE, -16)
        state_i = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state_i

    def linear_layer(self, state):
        omega = len(state) // 4

        # tx = x0 xor ... xor x_omega
        # ltx = l(tx)
        inputs_id, inputs_pos = get_inputs_parameter([state[i * 2] for i in range(omega)])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        tx = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        tx = self.ell_function(tx)

        # ty = y0 xor ... xor y_omega
        inputs_id, inputs_pos = get_inputs_parameter([state[i * 2 + 1] for i in range(omega)])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        ty = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        ty = self.ell_function(ty)

        # for (j = 2; j < nb; j += 2) {
        #       state[j-2] = state[j+nb] ^ state[j] ^ tmpy;
        #       state[j+nb] = state[j];
        #       state[j-1] = state[j+nb+1] ^ state[j+1] ^ tmpx;
        #       state[j+nb+1] = state[j+1];
        #     }
        state_old = deepcopy(state)
        for i in range(omega - 1):
            inputs_id, inputs_pos = get_inputs_parameter([state_old[(omega + i + 1) * 2],
                                                          state_old[(i + 1) * 2],
                                                          ty])
            self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
            state[i * 2] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            state[(omega + i + 1) * 2] = state_old[2 * (i + 1)]
            inputs_id, inputs_pos = get_inputs_parameter([state_old[(omega + i + 1) * 2 + 1],
                                                          state_old[(i + 1) * 2 + 1],
                                                          tx])
            self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
            state[i * 2 + 1] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            state[(omega + i + 1) * 2 + 1] = state_old[2 * (i + 1) + 1]

        # state[nb-2] = state[nb] ^ x0 ^ tmpy; state[nb] = x0;
        # state[nb-1] = state[nb+1] ^ y0 ^ tmpx; state[nb+1] = y0;
        inputs_id, inputs_pos = get_inputs_parameter([state_old[omega * 2], state_old[0], ty])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[(omega - 1) * 2] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        state[omega * 2] = state_old[0]
        inputs_id, inputs_pos = get_inputs_parameter([state_old[omega * 2 + 1], state_old[1], tx])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[(omega - 1) * 2 + 1] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        state[omega * 2 + 1] = state_old[1]

        return state

    def round_function(self, state, constant_ci, constant_r, r):
        # y0 = y0 xor ci[r mod 8]
        inputs_id, inputs_pos = get_inputs_parameter([state[1], constant_ci[r % 8]])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[1] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # y1 = y1 xor (r mod 2^32)
        inputs_id, inputs_pos = get_inputs_parameter([state[3], constant_r])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[3] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # xi, yi = alzette(xi, yi, ci)
        for i in range(len(state) // 2):
            state[2 * i], state[2 * i + 1] = self.alzette(state[2 * i], state[2 * i + 1], constant_ci[i])

        # Diffusion Layer
        # state = L(S)
        state = self.linear_layer(state)

        return state
