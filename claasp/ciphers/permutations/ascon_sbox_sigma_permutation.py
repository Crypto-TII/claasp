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
SBOX_SIZE = 5
WORD_SIZE = 64
LINEAR_LAYER_ROT = [[19, 28], [61, 39], [1, 6], [10, 17], [7, 41]]
PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 12}]
# fmt: off
ASCON_SBOX = [
    0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02, 0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
    0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18, 0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17
]
# fmt: on


class AsconSboxSigmaPermutation(Cipher):
    """
    Construct an instance of the AsconSboxSigmaPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
        sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=12)
        sage: ascon.number_of_rounds
        12

        sage: ascon.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, number_of_rounds=12):
        # cipher initialize
        self.state_bit_size = WORD_NUM * WORD_SIZE

        super().__init__(
            family_name="ascon_sbox_sigma",
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
            if r == 12 - number_of_rounds:
                state = self.round_function(state, ci, first_round=1)
            else:
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

    def round_function(self, state, ci, first_round=0):
        # W2 = W2 ^ ci
        self.add_constant_component(WORD_SIZE, ci)
        constant = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[2], constant])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[2] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        substitution_layer = []
        inputs_id = state[0].id + state[1].id + state[2].id + state[3].id + state[4].id
        for i in range(WORD_SIZE):
            if first_round:
                inputs_pos = [[i], [i + 64], [i], [i + 192], [i + 256]]
            else:
                inputs_pos = [[i]] * 5
            self.add_SBOX_component(inputs_id, inputs_pos, SBOX_SIZE, ASCON_SBOX)
            substitution_layer.append(ComponentState([self.get_current_component_id()], [list(range(SBOX_SIZE))]))

        linear_layer = []
        inputs_id = []
        for j in range(WORD_SIZE):
            inputs_id += substitution_layer[j].id
        for i in range(WORD_NUM):
            inputs_pos = [[i]] * 64
            self.add_sigma_component(inputs_id, inputs_pos, WORD_SIZE, LINEAR_LAYER_ROT[i])
            linear_layer.append(ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))]))

        return linear_layer
