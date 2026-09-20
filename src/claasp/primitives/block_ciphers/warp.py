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


from claasp.graph.bit_builder import BitGraphPrimitive, BitState, get_inputs_parameter
from claasp.primitive_inputs import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

STATE_NUM = 32
STATE_SIZE = 4

KEY_NUM = 32
KEY_SIZE = 4

SBOX = [0xC, 0xA, 0xD, 0x3, 0xE, 0xB, 0xF, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
SBOX_SIZE = 4

PBOX = [
    31,
    6,
    29,
    14,
    1,
    12,
    21,
    8,
    27,
    2,
    3,
    0,
    25,
    4,
    23,
    10,
    15,
    22,
    13,
    30,
    17,
    28,
    5,
    24,
    11,
    18,
    19,
    16,
    9,
    20,
    7,
    26,
]

ROUND_CONSTANTS = [
    [
        0x0,
        0x0,
        0x1,
        0x3,
        0x7,
        0xF,
        0xF,
        0xF,
        0xE,
        0xD,
        0xA,
        0x5,
        0xA,
        0x5,
        0xB,
        0x6,
        0xC,
        0x9,
        0x3,
        0x6,
        0xD,
        0xB,
        0x7,
        0xE,
        0xD,
        0xB,
        0x6,
        0xD,
        0xA,
        0x4,
        0x9,
        0x2,
        0x4,
        0x9,
        0x3,
        0x7,
        0xE,
        0xC,
        0x8,
        0x1,
        0x2,
    ],
    [
        0x4,
        0xC,
        0xC,
        0xC,
        0xC,
        0xC,
        0x8,
        0x4,
        0x8,
        0x4,
        0x8,
        0x4,
        0xC,
        0x8,
        0x0,
        0x4,
        0xC,
        0x8,
        0x4,
        0xC,
        0xC,
        0x8,
        0x4,
        0xC,
        0x8,
        0x4,
        0x8,
        0x0,
        0x4,
        0x8,
        0x0,
        0x4,
        0xC,
        0xC,
        0x8,
        0x0,
        0x0,
        0x4,
        0x8,
        0x4,
        0xC,
    ],
]


class Warp(BitGraphPrimitive):
    """
    Construct an instance of the Warp class.

    References: implementation and test vectors from [WARP]_.

    This class is used to store compact representations of a primitive, used to generate the corresponding primitive.

    INPUT:
    - ``number_of_rounds`` -- **integer** (default: `41`); number of rounds of the primitive.

    EXAMPLES::

        >>> primitive = Warp()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x3b91ccb836ac49c7', 126)
    """

    def __init__(self, number_of_rounds=41):
        self.state_bit_size = STATE_NUM * STATE_SIZE
        self.key_bit_size = KEY_NUM * KEY_SIZE
        self.total_rounds_number = number_of_rounds

        super().__init__(
            family_name="warp",
            primitive_type=BLOCK_CIPHER,
            primitive_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            primitive_inputs_bit_size=[self.state_bit_size, self.state_bit_size],
            primitive_output_bit_size=self.state_bit_size,
        )

        state: list[BitState] = []
        for i in range(STATE_NUM):
            p = BitState([INPUT_PLAINTEXT], [[k + i * STATE_SIZE for k in range(STATE_SIZE)]])
            state.append(p)

        key: list[BitState] = []
        for i in range(KEY_NUM):
            p = BitState([INPUT_KEY], [[k + i * KEY_SIZE for k in range(KEY_SIZE)]])
            key.append(p)

        key_0 = key[0 : KEY_NUM // 2]
        key_1 = key[KEY_NUM // 2 : KEY_NUM]
        key_0_1 = (key_0, key_1)

        for r in range(number_of_rounds):
            self.add_round()
            state = self._round_function(state, key_0_1, r)

            inputs_id, inputs_pos = get_inputs_parameter(state)
            if r == self.total_rounds_number - 1:
                self.add_primitive_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def _round_function(
        self,
        state: list[BitState],
        keys: tuple[list[BitState], list[BitState]],
        number_of_round: int,
    ) -> list[BitState]:
        state = self._sbox_xor_round_key(state, keys, number_of_round)
        state = self._xor_round_constants(state, number_of_round)

        if number_of_round != self.total_rounds_number - 1:
            state = self._permutation(state)
        return state

    def _sbox_xor_round_key(
        self,
        state: list[BitState],
        keys: tuple[list[BitState], list[BitState]],
        number_of_round: int,
    ) -> list[BitState]:
        state_new = []
        for i in range(0, STATE_NUM, 2):
            state_new.append(state[i])
            inputs_id, inputs_bit = get_inputs_parameter([state[i]])
            sbox = self.add_sbox_component(inputs_id, inputs_bit, SBOX_SIZE, SBOX)
            sbox_state = BitState([sbox.id], [list(range(SBOX_SIZE))])

            key_index = (number_of_round) % 2  # no minus 1 because the rounds are 0-indexed
            round_key = keys[key_index][i // 2]  # divide by two because iteration uses step 2
            inputs_id, inputs_bit = get_inputs_parameter([sbox_state, round_key, state[i + 1]])
            xor = self.add_xor_component(inputs_id, inputs_bit, STATE_SIZE)

            state_new.append(BitState([xor.id], [list(range(STATE_SIZE))]))

        return state_new

    def _xor_round_constants(self, state: list[BitState], number_of_round: int) -> list[BitState]:
        const_0_r = self.add_constant_component(STATE_SIZE, ROUND_CONSTANTS[0][number_of_round])
        const_0_r = BitState([const_0_r.id], [list(range(STATE_SIZE))])
        inputs_id, inputs_bit = get_inputs_parameter([state[1], const_0_r])
        xor_x1_const_0_r = self.add_xor_component(inputs_id, inputs_bit, STATE_SIZE)
        state[1] = BitState([xor_x1_const_0_r.id], [list(range(STATE_SIZE))])

        const_1_r = self.add_constant_component(STATE_SIZE, ROUND_CONSTANTS[1][number_of_round])
        const_1_r = BitState([const_1_r.id], [list(range(STATE_SIZE))])
        inputs_id, inputs_bit = get_inputs_parameter([state[3], const_1_r])
        xor_x3_const_1_r = self.add_xor_component(inputs_id, inputs_bit, STATE_SIZE)
        state[3] = BitState([xor_x3_const_1_r.id], [list(range(STATE_SIZE))])

        return state

    def _permutation(self, state: list[BitState]) -> list[BitState]:
        inputs_id, inputs_bit = get_inputs_parameter(state)

        perm = self.add_permutation_component(
            inputs_id, inputs_bit, STATE_SIZE * STATE_NUM, PBOX, word_size=4
        )

        state_new = []
        for i in range(STATE_NUM):
            p = BitState([perm.id], [[k + i * STATE_SIZE for k in range(STATE_SIZE)]])
            state_new.append(p)

        return state_new
