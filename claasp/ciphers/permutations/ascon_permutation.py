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
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION
from claasp.utils.utils import get_inputs_parameter
from claasp.DTOs.component_state import ComponentState


WORD_NUM = 5
WORD_SIZE = 64
LINEAR_LAYER_ROT = [[19, 28], [61, 39], [1, 6], [10, 17], [7, 41]]
PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 12}]


class AsconPermutation(Cipher):
    """
    Construct an instance of the AsconPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
        sage: ascon = AsconPermutation(number_of_rounds=12)
        sage: ascon.number_of_rounds
        12

        sage: ascon.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, number_of_rounds=12):
        self.state_bit_size = WORD_NUM * WORD_SIZE

        super().__init__(
            family_name="ascon",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        # word initialization
        state = []
        for i in range(WORD_NUM):
            p = ComponentState([INPUT_PLAINTEXT], [[k + i * WORD_SIZE for k in range(WORD_SIZE)]])
            state.append(p)

        # round function
        for r in range(12 - number_of_rounds, 12):
            # initial current round element
            self.add_round()

            # round parameter
            ci = 0xF0 - r * 0x10 + r * 0x1

            # round function
            state = self.round_function(state, ci)

            # round output
            inputs = []
            for i in range(WORD_NUM):
                inputs.append(state[i])
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            if r == 11:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)
            # add all components to the round

    def round_function(self, state, ci):
        # add round constant
        # W2 = W2 ^ ci
        self.add_constant_component(WORD_SIZE, ci)
        c = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[2], c])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[2] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # substitution layer
        # S[0] ^= S[4]
        inputs_id, inputs_pos = get_inputs_parameter([state[0], state[4]])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[0] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # S[4] ^= S[3]
        inputs_id, inputs_pos = get_inputs_parameter([state[4], state[3]])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[4] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # S[2] ^= S[1]
        inputs_id, inputs_pos = get_inputs_parameter([state[2], state[1]])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[2] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # T = [(~S[i]) & S[(i + 1) % 5] for i in range(5)]
        T = []
        for i in range(WORD_NUM):
            self.add_NOT_component(state[i].id, state[i].input_bit_positions, WORD_SIZE)
            s = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            inputs_id, inputs_pos = get_inputs_parameter([s, state[(i + 1) % WORD_NUM]])
            self.add_AND_component(inputs_id, inputs_pos, WORD_SIZE)
            T.append(ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]))

        # S[i] ^= T[(i+1)%5] for i in range(5)
        for i in range(WORD_NUM):
            inputs_id, inputs_pos = get_inputs_parameter([state[i], T[(i + 1) % WORD_NUM]])
            self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
            state[i] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # S[1] ^= S[0]
        inputs_id, inputs_pos = get_inputs_parameter([state[1], state[0]])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[1] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # S[3] ^= S[2]
        inputs_id, inputs_pos = get_inputs_parameter([state[3], state[2]])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[3] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # S[0] ^= S[4]
        inputs_id, inputs_pos = get_inputs_parameter([state[0], state[4]])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[0] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # S[2] = ~S[2]
        self.add_NOT_component(state[2].id, state[2].input_bit_positions, WORD_SIZE)
        state[2] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs = []
        for i in range(WORD_NUM):
            inputs.append(state[i])
        inputs_id, inputs_pos = get_inputs_parameter(inputs)
        self.add_intermediate_output_component(inputs_id, inputs_pos, self.state_bit_size, "round_output_nonlinear")

        # linear layer
        # S[i] ^= rotr(S[i], rot0) ^ rotr(S[i], rot1)
        for i in range(WORD_NUM):
            self.add_rotate_component(state[i].id, state[i].input_bit_positions, WORD_SIZE, LINEAR_LAYER_ROT[i][0])
            s1 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            self.add_rotate_component(state[i].id, state[i].input_bit_positions, WORD_SIZE, LINEAR_LAYER_ROT[i][1])
            s2 = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            inputs_id, inputs_pos = get_inputs_parameter([state[i], s1, s2])
            self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
            state[i] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state
