
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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY
from claasp.utils.utils import simplify_inputs, get_inputs_parameter

KEY_NUM = 8
KEY_SIZE = 16
STATE_NUM = 4
S_BOX_SIZE = 4
STATE_SIZE = 32
KEY_ROT = [2, 12]
PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 40}]
S_BOX = [0x8, 0x4, 0x6, 0xa, 0x2, 0xd, 0xc, 0x1, 0x5, 0xb, 0xf, 0x0, 0x3, 0xe, 0x9, 0x7]
P_BOX = [
    [16, 8, 0, 24, 17, 9, 1, 25, 18, 10, 2, 26, 19, 11, 3, 27, 20, 12,
     4, 28, 21, 13, 5, 29, 22, 14, 6, 30, 23, 15, 7, 31],
    [8, 0, 24, 16, 9, 1, 25, 17, 10, 2, 26, 18, 11, 3, 27, 19, 12,
     4, 28, 20, 13, 5, 29, 21, 14, 6, 30, 22, 15, 7, 31, 23],
    [0, 24, 16, 8, 1, 25, 17, 9, 2, 26, 18, 10, 3, 27, 19, 11,
     4, 28, 20, 12, 5, 29, 21, 13, 6, 30, 22, 14, 7, 31, 23, 15],
    [24, 16, 8, 0, 25, 17, 9, 1, 26, 18, 10, 2, 27, 19, 11,
     3, 28, 20, 12, 4, 29, 21, 13, 5, 30, 22, 14, 6, 31, 23, 15, 7]
]
ROUND_CONSTANT = [0x80000001, 0x80000003, 0x80000007, 0x8000000F, 0x8000001F, 0x8000003E, 0x8000003D, 0x8000003B,
                  0x80000037, 0x8000002F, 0x8000001E, 0x8000003C, 0x80000039, 0x80000033, 0x80000027, 0x8000000E,
                  0x8000001D, 0x8000003A, 0x80000035, 0x8000002B, 0x80000016, 0x8000002C, 0x80000018, 0x80000030,
                  0x80000021, 0x80000002, 0x80000005, 0x8000000B, 0x80000017, 0x8000002E, 0x8000001C, 0x80000038,
                  0x80000031, 0x80000023, 0x80000006, 0x8000000D, 0x8000001B, 0x80000036, 0x8000002D, 0x8000001A,
                  0x80000034, 0x80000029, 0x80000012, 0x80000024, 0x80000008, 0x80000011, 0x80000022, 0x80000004
                  ]


class GiftSboxPermutation(Cipher):
    """
    Construct an instance of the GIFTSboxPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `40`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.gift_sbox_permutation import GiftSboxPermutation
        sage: gift = GiftSboxPermutation(number_of_rounds=40)
        sage: gift.number_of_rounds
        40

        sage: gift.component_from(0, 0).id
        'sbox_0_0'
    """

    def __init__(self, number_of_rounds=40):
        self.state_bit_size = STATE_NUM * STATE_SIZE
        self.key_bit_size = KEY_NUM * KEY_SIZE

        super().__init__(family_name="gift_sbox",
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
        for round_number in range(number_of_rounds):
            # initial current round element
            self.add_round()

            # round constant
            ci = ROUND_CONSTANT[round_number]

            # update key schedule
            if round_number != 0:
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
            if round_number == number_of_rounds - 1:
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
        # using sbox
        p = ComponentState(["" for _ in range(STATE_SIZE)], [[] for _ in range(STATE_SIZE)])
        state_new = [deepcopy(p) for _ in range(STATE_NUM)]
        for k in range(STATE_SIZE):
            inputs_id = []
            inputs_pos = []
            for i in range(STATE_NUM):
                inputs_id = inputs_id + state[i].id
                inputs_pos = inputs_pos + [[state[i].input_bit_positions[0][k]]]
            inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
            self.add_SBOX_component(inputs_id, inputs_pos, S_BOX_SIZE, S_BOX)
            for i in range(STATE_NUM):
                state_new[i].id[k] = self.get_current_component_id()
                state_new[i].input_bit_positions[k] = [i]
        state = deepcopy(state_new)

        # permbits
        # Si = permutation_i(Si)
        for i in range(STATE_NUM):
            inputs_id, inputs_pos = get_inputs_parameter([state[i]])
            self.add_permutation_component(inputs_id, inputs_pos, STATE_SIZE, deepcopy(P_BOX[i]))
            state[i] = ComponentState([self.get_current_component_id()], [list(range(STATE_SIZE))])

        # addroundkey
        # S2 = S2 xor U
        inputs_id, inputs_pos = get_inputs_parameter([state[2], round_key_u])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[2] = ComponentState([self.get_current_component_id()], [list(range(STATE_SIZE))])

        # S1 = S1 xor V
        inputs_id, inputs_pos = get_inputs_parameter([state[1], round_key_v])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[1] = ComponentState([self.get_current_component_id()], [list(range(STATE_SIZE))])

        # S3 = S3 xor ci
        # add round constant
        self.add_constant_component(STATE_SIZE, ci)
        c = ComponentState([self.get_current_component_id()], [list(range(STATE_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[3], c])
        self.add_XOR_component(inputs_id, inputs_pos, STATE_SIZE)
        state[3] = ComponentState([self.get_current_component_id()], [list(range(STATE_SIZE))])

        return state
