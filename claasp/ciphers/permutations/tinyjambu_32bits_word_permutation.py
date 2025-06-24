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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY, PERMUTATION

WORD_SIZE = 32
STATE_SIZE = 128
PARAMETERS_CONFIGURATION_LIST = [{"key_bit_size": 128, "number_of_rounds": 640}]


class TinyJambuWordBasedPermutation(Cipher):
    """
    Construct an instance of the TinyJambuWordBasedPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
        - ``number_of_rounds`` -- **integer** (default: `640`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.permutations.tinyjambu_32bits_word_permutation import TinyJambuWordBasedPermutation
        sage: tinyjambu = TinyJambuWordBasedPermutation()
        sage: tinyjambu.number_of_rounds
        20

        sage: tinyjambu.component_from(0, 0).id
        'and_0_0'
    """

    def __init__(self, key_bit_size=128, number_of_rounds=640):
        number_of_words_in_round = int(number_of_rounds / WORD_SIZE)
        super().__init__(
            family_name="tinyjambu_word_based",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[STATE_SIZE, key_bit_size],
            cipher_output_bit_size=STATE_SIZE,
        )

        # state initialization
        state = []
        for i in range(int(STATE_SIZE / WORD_SIZE)):
            state.append(ComponentState([INPUT_PLAINTEXT], [[i * 32 + j for j in range(WORD_SIZE)]]))

        # key initialization
        key = []
        for i in range(int(key_bit_size / WORD_SIZE)):
            key.append(ComponentState([INPUT_KEY], [[i * 32 + j for j in range(WORD_SIZE)]]))

        for round_number in range(number_of_words_in_round):
            # round function
            # initial current round element
            self.add_round()

            # round function
            state = self.round_function(state, key, round_number)

            # round output
            inputs = []
            for i in range(len(state)):
                inputs.append(state[i])
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            if round_number == number_of_words_in_round - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, STATE_SIZE)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, STATE_SIZE)

    def round_function(self, state, key, r):
        # feedback = s0 xor s47 xor (∼ (s70 and s85)) xor s91 xor kr
        # ...
        # feedback = s31 xor s78 xor (~(s101 and s116)) xor s122 xor kr
        # each time executes 32bits
        input1 = ComponentState(
            [state[2].id[0], state[3].id[0]],
            [
                [state[2].input_bit_positions[0][i] for i in range(70 - WORD_SIZE * 2, WORD_SIZE)],
                [state[3].input_bit_positions[0][i] for i in range(70 + 32 - WORD_SIZE * 3)],
            ],
        )
        input2 = ComponentState(
            [state[2].id[0], state[3].id[0]],
            [
                [state[2].input_bit_positions[0][i] for i in range(85 - WORD_SIZE * 2, WORD_SIZE)],
                [state[3].input_bit_positions[0][i] for i in range(85 + 32 - WORD_SIZE * 3)],
            ],
        )
        inputs_id, inputs_pos = get_inputs_parameter([input1, input2])
        self.add_AND_component(inputs_id, inputs_pos, WORD_SIZE)

        inputs_id = [self.get_current_component_id()]
        inputs_pos = [list(range(WORD_SIZE))]
        self.add_NOT_component(inputs_id, inputs_pos, WORD_SIZE)

        temp = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        input1 = ComponentState(
            [state[1].id[0], state[2].id[0]],
            [
                [state[1].input_bit_positions[0][i] for i in range(47 - WORD_SIZE, WORD_SIZE)],
                [state[2].input_bit_positions[0][i] for i in range(47 + 32 - WORD_SIZE * 2)],
            ],
        )
        input2 = ComponentState(
            [state[2].id[0], state[3].id[0]],
            [
                [state[2].input_bit_positions[0][i] for i in range(91 - WORD_SIZE * 2, WORD_SIZE)],
                [state[3].input_bit_positions[0][i] for i in range(91 + 32 - WORD_SIZE * 3)],
            ],
        )
        inputs_id, inputs_pos = get_inputs_parameter([state[0], input1, input2, temp, key[r % len(key)]])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        temp = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        for i in range(len(state) - 1):
            state[i] = deepcopy(state[i + 1])

        state[-1] = deepcopy(temp)

        return state
