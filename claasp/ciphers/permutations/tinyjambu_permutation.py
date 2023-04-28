
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
from claasp.utils.utils import get_inputs_parameter
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

STATE_SIZE = 128
PARAMETERS_CONFIGURATION_LIST = [{'key_bit_size': 128, 'number_of_rounds': 640}]


class TinyJambuPermutation(Cipher):
    """
    Construct an instance of the TinyJambuPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
        - ``number_of_rounds`` -- **integer** (default: `640`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.permutations.tinyjambu_permutation import TinyJambuPermutation
        sage: tinyjambu = TinyJambuPermutation()
        sage: tinyjambu.number_of_rounds
        640

        sage: tinyjambu.component_from(0, 0).id
        'and_0_0'
    """

    def __init__(self, key_bit_size=128, number_of_rounds=640):

        super().__init__(family_name="tinyjambu",
                         cipher_type="permutation",
                         cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[key_bit_size, STATE_SIZE],
                         cipher_output_bit_size=STATE_SIZE)

        # state initialization
        state = []
        for i in range(STATE_SIZE):
            state.append(ComponentState([INPUT_PLAINTEXT], [[i]]))

        # key initialization
        key = []
        for i in range(key_bit_size):
            key.append(ComponentState([INPUT_KEY], [[i]]))

        for round_number in range(number_of_rounds):
            # round function
            # initial current round element
            self.add_round()

            # round function
            state = self.round_function(state, key, round_number)

            # round output
            inputs = []
            for i in range(STATE_SIZE):
                inputs.append(state[i])
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, STATE_SIZE)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, STATE_SIZE)

    def round_function(self, state, key, r):
        # feedback = s0 xor s47 xor (∼ (s70 and s85)) xor s91 xor kr
        inputs_id, inputs_pos = get_inputs_parameter([state[70], state[85]])
        self.add_AND_component(inputs_id, inputs_pos, 1)
        self.add_NOT_component([self.get_current_component_id()], [[0]], 1)
        temp = ComponentState([self.get_current_component_id()], [[0]])
        inputs_id, inputs_pos = get_inputs_parameter([state[0], state[47], state[91], temp, key[(r) % len(key)]])
        self.add_XOR_component(inputs_id, inputs_pos, 1)
        temp = ComponentState([self.get_current_component_id()], [[0]])

        for i in range(STATE_SIZE - 1):
            state[i] = deepcopy(state[i + 1])
        state[STATE_SIZE - 1] = deepcopy(temp)

        return state
