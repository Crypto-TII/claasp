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
FSR_POLYNOMIAL = [[0], [47], [70, 85], [91]]
FSR_LOOPS = 32
PARAMETERS_CONFIGURATION_LIST = [{"key_bit_size": 128, "number_of_rounds": 640}]


class TinyJambuFSRWordBasedPermutation(Cipher):
    """
    Construct an instance of the TinyJambuFSRWordBasedPermutation class with fsr component.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
        - ``number_of_rounds`` -- **integer** (default: `640`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.permutations.tinyjambu_fsr_32bits_word_permutation import TinyJambuFSRWordBasedPermutation
        sage: tinyjambu = TinyJambuFSRWordBasedPermutation()
        sage: tinyjambu.number_of_rounds
        20

        sage: tinyjambu.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, key_bit_size=128, number_of_rounds=640):
        number_of_words_in_round = int(number_of_rounds / WORD_SIZE)
        super().__init__(
            family_name="tinyjambu_fsr_word_based",
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

            self.add_constant_component(WORD_SIZE, 0xFFFFFFFF)
            not_constant = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

            # round function
            state = self.round_function(state, key, not_constant, round_number)

            # round output
            inputs = []
            for i in range(len(state)):
                inputs.append(state[i])
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            if round_number == number_of_words_in_round - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, STATE_SIZE)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, STATE_SIZE)

    def round_function(self, state, key, not_constant, r):
        # feedback = s0 xor s47 xor (∼ (s70 and s85)) xor s91 xor kr
        # polynomial = s0 xor x47 xor (s70*s85 xor 1) xor s91 xor kr
        # = (s0 xor x47 xor s70*s85 xor s91) xor kr xor 1
        # = fsr xor kr xor 1
        inputs_id, inputs_pos = get_inputs_parameter([state[0], state[1], state[2], state[3]])
        self.add_FSR_component(inputs_id, inputs_pos, STATE_SIZE, [[[STATE_SIZE, FSR_POLYNOMIAL, []]], 1, FSR_LOOPS])
        fsr_output = ComponentState([self.get_current_component_id()], [list(range(3 * WORD_SIZE, 4 * WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([fsr_output, key[r % len(key)], not_constant])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        round_output = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        for i in range(len(state) - 1):
            state[i] = deepcopy(state[i + 1])
        state[-1] = deepcopy(round_output)

        return state
