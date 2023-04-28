
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
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import get_inputs_parameter
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

KEY_NUM = 8
KEY_SIZE = 16
STATE_NUM = 4
STATE_SIZE = 32
KEY_ROT = [2, 12]
PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 40}]
P_BOX = [
    [2, 6, 10, 14, 18, 22, 26, 30, 1, 5, 9, 13, 17, 21, 25, 29,
     0, 4, 8, 12, 16, 20, 24, 28, 3, 7, 11, 15, 19, 23, 27, 31],
    [1, 5, 9, 13, 17, 21, 25, 29, 0, 4, 8, 12, 16, 20, 24, 28,
     3, 7, 11, 15, 19, 23, 27, 31, 2, 6, 10, 14, 18, 22, 26, 30],
    [0, 4, 8, 12, 16, 20, 24, 28, 3, 7, 11, 15, 19, 23, 27, 31,
     2, 6, 10, 14, 18, 22, 26, 30, 1, 5, 9, 13, 17, 21, 25, 29],
    [3, 7, 11, 15, 19, 23, 27, 31, 2, 6, 10, 14, 18, 22, 26, 30,
     1, 5, 9, 13, 17, 21, 25, 29, 0, 4, 8, 12, 16, 20, 24, 28]
]
ROUND_CONSTANT = [0x80000001, 0x80000003, 0x80000007, 0x8000000F, 0x8000001F, 0x8000003E, 0x8000003D, 0x8000003B,
                  0x80000037, 0x8000002F, 0x8000001E, 0x8000003C, 0x80000039, 0x80000033, 0x80000027, 0x8000000E,
                  0x8000001D, 0x8000003A, 0x80000035, 0x8000002B, 0x80000016, 0x8000002C, 0x80000018, 0x80000030,
                  0x80000021, 0x80000002, 0x80000005, 0x8000000B, 0x80000017, 0x8000002E, 0x8000001C, 0x80000038,
                  0x80000031, 0x80000023, 0x80000006, 0x8000000D, 0x8000001B, 0x80000036, 0x8000002D, 0x8000001A,
                  0x80000034, 0x80000029, 0x80000012, 0x80000024, 0x80000008, 0x80000011, 0x80000022, 0x80000004
                  ]


class GiftPermutation(Cipher):
    """
    Construct an instance of the GIFTPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `40`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
        sage: gift = GiftPermutation(number_of_rounds=40)
        sage: gift.number_of_rounds
        40

        sage: gift.component_from(0, 0).id
        'and_0_0'
    """

    def __init__(self, number_of_rounds=40):
        self.state_bit_size = STATE_NUM * STATE_SIZE
        self.key_bit_size = KEY_NUM * KEY_SIZE

        super().__init__(family_name='gift',
                         cipher_type="permutation",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.state_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.state_bit_size)

        # state initialization
        state = []
        for i in range(STATE_NUM):
            p = ComponentState([INPUT_PLAINTEXT], [[k + i * STATE_SIZE for k in range(STATE_SIZE)]])
            state.append(p)

        # key initialization
        key_list = []
        for i in range(KEY_NUM):
            p = ComponentState([INPUT_KEY], [[k + i * KEY_SIZE for k in range(KEY_SIZE)]])
            key_list.append(p)

        # round function
        for r in range(number_of_rounds):
            # initial current round element
            self.add_round()

            # round constant
            ci = ROUND_CONSTANT[r]

            # update key schedule
            if r != 0:
                key_list = self.key_schedule(key_list)
            round_key_u = ComponentState(deepcopy(key_list[2].id) + deepcopy(key_list[3].id),
                                         deepcopy(key_list[2].input_bit_positions) +
                                         deepcopy(key_list[3].input_bit_positions))
            round_key_v = ComponentState(deepcopy(key_list[6].id) + deepcopy(key_list[7].id),
                                         deepcopy(key_list[6].input_bit_positions) +
                                         deepcopy(key_list[7].input_bit_positions))
            # round function
            state = self.round_function(state, round_key_u, round_key_v, ci)

            # round output
            inputs = []
            for i in range(STATE_NUM):
                inputs.append(state[i])
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            if r == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def key_schedule(self, key):
        # key update
        key_new = []
        # W0 = W6 >>> 2
        self.add_rotate_component(key[6].id, key[6].input_bit_positions, KEY_SIZE, KEY_ROT[0])
        component = ComponentState([self.get_current_component_id()], [list(range(KEY_SIZE))])
        key_new.append(component)
        # W1 = W7 >>> 12
        self.add_rotate_component(key[7].id, key[7].input_bit_positions, KEY_SIZE, KEY_ROT[1])
        component = ComponentState([self.get_current_component_id()], [list(range(KEY_SIZE))])
        key_new.append(component)
        # W2..W7 = W0..W5
        for i in range(6):
            key_new.append(deepcopy(key[i]))

        return key_new

    def round_function(self, state, round_key_u, round_key_v, ci):
        # subcells
        # S1 = S1 xor (S0 & S2)
        inputs_id, inputs_pos = get_inputs_parameter([state[0], state[2]])
        self.add_AND_component(inputs_id, inputs_pos, STATE_SIZE)
        input_bit_positions = list(range(STATE_SIZE))
        temp = ComponentState([self.get_current_component_id()], [input_bit_positions])
        inputs_id, inputs_pos = get_inputs_parameter([state[1], temp])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[1] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S0 = S0 xor (S1 & S3)
        inputs_id, inputs_pos = get_inputs_parameter([state[1], state[3]])
        self.add_AND_component(inputs_id, inputs_pos, STATE_SIZE)
        temp = ComponentState([self.get_current_component_id()], [input_bit_positions])
        inputs_id, inputs_pos = get_inputs_parameter([state[0], temp])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[0] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S2 = S2 xor (S0 or S1)
        inputs_id, inputs_pos = get_inputs_parameter([state[0], state[1]])
        self.add_OR_component(inputs_id, inputs_pos, STATE_SIZE)
        temp = ComponentState([self.get_current_component_id()], [input_bit_positions])
        inputs_id, inputs_pos = get_inputs_parameter([state[2], temp])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[2] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S3 = S3 xor S2
        inputs_id, inputs_pos = get_inputs_parameter([state[2], state[3]])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[3] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S1 = S1 xor S3
        inputs_id, inputs_pos = get_inputs_parameter([state[1], state[3]])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[1] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S3 = ~S3
        self.add_NOT_component(state[3].id, state[3].input_bit_positions, STATE_SIZE)
        state[3] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S2 = S2 xor (S0 & S1)
        inputs_id, inputs_pos = get_inputs_parameter([state[0], state[1]])
        self.add_AND_component(inputs_id, inputs_pos, STATE_SIZE)
        temp = ComponentState([self.get_current_component_id()], [input_bit_positions])
        inputs_id, inputs_pos = get_inputs_parameter([state[2], temp])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[2] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S0, S1, S2, S3 = S3, S1, S2, S0
        temp = deepcopy(state[0])
        state[0] = deepcopy(state[3])
        state[3] = deepcopy(temp)

        # permbits
        # Si = permutation_i(Si)
        for i in range(STATE_NUM):
            state[i] = ComponentState(state[i].id, [deepcopy(P_BOX[i])])

        # addroundkey
        # S2 = S2 xor U
        inputs_id, inputs_pos = get_inputs_parameter([state[2], round_key_u])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[2] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S1 = S1 xor V
        inputs_id, inputs_pos = get_inputs_parameter([state[1], round_key_v])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[1] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        # S3 = S3 xor ci
        # add round constant
        self.add_constant_component(STATE_SIZE, ci)
        c = ComponentState([self.get_current_component_id()], [input_bit_positions])
        inputs_id, inputs_pos = get_inputs_parameter([state[3], c])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[3] = ComponentState([self.get_current_component_id()], [input_bit_positions])

        return state
