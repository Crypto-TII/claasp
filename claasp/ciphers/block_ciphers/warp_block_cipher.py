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

from typing import List, Tuple

from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, BLOCK_CIPHER
from claasp.utils.utils import get_inputs_parameter

STATE_NUM = 32
STATE_SIZE = 4

KEY_NUM = 32
KEY_SIZE = 4

SBOX = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
SBOX_SIZE = 4

PBOX = [
    31, 6, 29, 14, 1, 12, 21, 8, 27, 2, 3, 0, 25, 4, 23, 10,
    15, 22, 13, 30, 17, 28, 5, 24, 11, 18, 19, 16, 9, 20, 7, 26
]

ROUND_CONSTANTS = [
    [
        0x0, 0x0, 0x1, 0x3, 0x7, 0xf, 0xf, 0xf, 0xe, 0xd, 0xa, 0x5, 0xa, 0x5, 0xb, 0x6, 0xc, 0x9, 0x3, 0x6,
        0xd, 0xb, 0x7, 0xe, 0xd, 0xb, 0x6, 0xd, 0xa, 0x4, 0x9, 0x2, 0x4, 0x9, 0x3, 0x7, 0xe, 0xc, 0x8, 0x1, 0x2
    ],
    [
        0x4, 0xc, 0xc, 0xc, 0xc, 0xc, 0x8, 0x4, 0x8, 0x4, 0x8, 0x4, 0xc, 0x8, 0x0, 0x4, 0xc, 0x8, 0x4, 0xc,
        0xc, 0x8, 0x4, 0xc, 0x8, 0x4, 0x8, 0x0, 0x4, 0x8, 0x0, 0x4, 0xc, 0xc, 0x8, 0x0, 0x0, 0x4, 0x8, 0x4, 0xc
    ]
]


class WarpBlockCipher(Cipher):
    """
    Construct an instance of the WarpBlockCipher class.

    References: implementation and test vectors from [WARP]_.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:
    - ``number_of_rounds`` -- **integer** (default: `41`); number of rounds of the cipher.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.warp_block_cipher import WarpBlockCipher
        sage: warp = WarpBlockCipher(number_of_rounds=1)
        sage: warp.number_of_rounds
        1
        sage: warp = WarpBlockCipher()
        sage: plaintext = 0x0123456789abcdeffedcba9876543210
        sage: key = 0x0123456789abcdeffedcba9876543210
        sage: hex(warp.evaluate([plaintext, key]))
        '0x24ce0a8efd9f32de529d5fdf45703a8d'
        sage: warp.component_from(0, 0).id
        'sbox_0_0'
    """

    def __init__(self, number_of_rounds=41):
        self.state_bit_size = STATE_NUM * STATE_SIZE
        self.key_bit_size = KEY_NUM * KEY_SIZE
        self.total_rounds_number = number_of_rounds

        super().__init__(
            family_name='warp',
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.state_bit_size, self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        state: List[ComponentState] = []
        for i in range(STATE_NUM):
            p = ComponentState([INPUT_PLAINTEXT], [[k + i * STATE_SIZE for k in range(STATE_SIZE)]])
            state.append(p)

        key: List[ComponentState] = []
        for i in range(KEY_NUM):
            p = ComponentState([INPUT_KEY], [[k + i * KEY_SIZE for k in range(KEY_SIZE)]])
            key.append(p)

        key_0 = key[0: KEY_NUM // 2]
        key_1 = key[KEY_NUM // 2: KEY_NUM]
        key_0_1 = (key_0, key_1)

        for r in range(number_of_rounds):
            self.add_round()
            state = self._round_function(state, key_0_1, r)

            inputs_id, inputs_pos = get_inputs_parameter(state)
            if r == self.total_rounds_number - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def _round_function(self,
                        state: List[ComponentState],
                        keys: Tuple[List[ComponentState],
                                    List[ComponentState]],
                        number_of_round: int) -> List[ComponentState]:
        state = self._sbox_xor_round_key(state, keys, number_of_round)
        state = self._xor_round_constants(state, number_of_round)

        if number_of_round != self.total_rounds_number - 1:
            state = self._permutation(state)
        return state

    def _sbox_xor_round_key(self,
                            state: List[ComponentState],
                            keys: Tuple[List[ComponentState],
                                        List[ComponentState]],
                            number_of_round: int) -> List[ComponentState]:
        state_new = []
        for i in range(0, STATE_NUM, 2):
            state_new.append(state[i])
            inputs_id, inputs_bit = get_inputs_parameter([state[i]])
            sbox = self.add_sbox_component(inputs_id, inputs_bit, SBOX_SIZE, SBOX)
            sbox_state = ComponentState([sbox.id], [list(range(SBOX_SIZE))])

            key_index = (number_of_round) % 2  # no minus 1 because the rounds are 0-indexed
            round_key = keys[key_index][i // 2]  # divide by two because iteration uses step 2
            inputs_id, inputs_bit = get_inputs_parameter([sbox_state, round_key, state[i + 1]])
            xor = self.add_xor_component(inputs_id, inputs_bit, STATE_SIZE)

            state_new.append(ComponentState([xor.id], [list(range(STATE_SIZE))]))

        return state_new

    def _xor_round_constants(self, state: List[ComponentState], number_of_round: int) -> List[ComponentState]:
        const_0_r = self.add_constant_component(STATE_SIZE, ROUND_CONSTANTS[0][number_of_round])
        const_0_r = ComponentState([const_0_r.id], [list(range(STATE_SIZE))])
        inputs_id, inputs_bit = get_inputs_parameter([state[1], const_0_r])
        xor_x1_const_0_r = self.add_xor_component(inputs_id, inputs_bit, STATE_SIZE)
        state[1] = ComponentState([xor_x1_const_0_r.id], [list(range(STATE_SIZE))])

        const_1_r = self.add_constant_component(STATE_SIZE, ROUND_CONSTANTS[1][number_of_round])
        const_1_r = ComponentState([const_1_r.id], [list(range(STATE_SIZE))])
        inputs_id, inputs_bit = get_inputs_parameter([state[3], const_1_r])
        xor_x3_const_1_r = self.add_xor_component(inputs_id, inputs_bit, STATE_SIZE)
        state[3] = ComponentState([xor_x3_const_1_r.id], [list(range(STATE_SIZE))])

        return state

    def _permutation(self, state: List[ComponentState]) -> List[ComponentState]:
        inputs_id, inputs_bit = get_inputs_parameter(state)

        perm = self.add_permutation_component(inputs_id, inputs_bit, STATE_SIZE * STATE_NUM, PBOX, word_size=4)

        state_new = []
        for i in range(STATE_NUM):
            p = ComponentState([perm.id], [[k + i * STATE_SIZE for k in range(STATE_SIZE)]])
            state_new.append(p)

        return state_new
