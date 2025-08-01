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

GASTON_NROWS = 5
WORD_SIZE = 64

# parameters for theta
GASTON_t = [25, 32, 52, 60, 63]

GASTON_r = 1
GASTON_s = 18
GASTON_u = 23

# rho-east rotation offsets
GASTON_e = [0, 60, 22, 27, 4]

# rho-west rotation offsets
GASTON_w = [0, 56, 31, 46, 43]

# gaston round constant
GASTON_rc = [0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B]
# fmt: off
SBOX = [
    0x00, 0x05, 0x0a, 0x0b, 0x14, 0x11, 0x16, 0x17, 0x09, 0x0c, 0x03, 0x02, 0x0d, 0x08, 0x0f, 0x0e,
    0x12, 0x15, 0x18, 0x1b, 0x06, 0x01, 0x04, 0x07, 0x1a, 0x1d, 0x10, 0x13, 0x1e, 0x19, 0x1c, 0x1f,
]
# fmt: on

PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 12}]


class GastonSboxThetaPermutation(Cipher):
    """
    Construct an instance of the Gaston Permutation class using the Sbox component and the Theta mixing layer,
    described as a matrix multiplication to make cipher inversion easy.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.gaston_sbox_theta_permutation import GastonSboxThetaPermutation
        sage: gaston = GastonSboxThetaPermutation(number_of_rounds=12)

        sage: plaintext = 0x00000000000000010000000000000001000000000000000100000000000000010000000000000001
        sage: ciphertext = 0x202d7fa691663e77043cb03594656fcdf6747f2da9cd9200ec3380fde8ec84d565247e6763406084
        sage: print(gaston.evaluate([plaintext])==ciphertext)
        True

        sage: plaintext = 0x0
        sage: ciphertext = 0x88B326096BEBC6356CA8FB64BC5CE6CAF1CE3840D819071354D70067438689B5F17FE863F958F32B
        sage: print(gaston.evaluate([plaintext])==ciphertext)
        True

        sage: plaintext=0x1F4AD9906DA6A2544B84D7F83F2BDDFA468A0853578A00E36C05A0506DF7F66E4EFB22112453C964
        sage: ciphertext=0x1BA89B5B5C4583B622135709AE53417D9847B975E9EC9F3DCE042DF2A402591D563EC68FC30307EA
        sage: print(gaston.evaluate([plaintext])==ciphertext)
        True

        sage: plaintext=0xFFFFFFFFFFFFFFFF0123456789ABCDEFFEDCBA9876543210AAAAAAAAAAAAAAAA0101010101010101
        sage: ciphertext=0x3117D51B14937067338F17F773C13F79DFB86E0868D252AB0D461D35EB863DE708BCE3E354C7231A
        sage: print(gaston.evaluate([plaintext])==ciphertext)
        True
    """

    def __init__(self, number_of_rounds=12):
        self.state_bit_size = GASTON_NROWS * WORD_SIZE

        super().__init__(
            family_name="gaston",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        # gaston state initialization
        state = []
        for row in range(GASTON_NROWS):
            p = ComponentState([INPUT_PLAINTEXT], [[i + row * WORD_SIZE for i in range(WORD_SIZE)]])
            state.append(p)

        for round_number in range(12 - number_of_rounds, 12):
            self.add_round()
            # gaston round function
            state = self.gaston_round_function(state, GASTON_rc[round_number])
            # gaston round output
            inputs_id, inputs_pos = get_inputs_parameter([state[i] for i in range(GASTON_NROWS)])
            if round_number == 11:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def gaston_round_function(self, state, rc):
        state = self.gaston_rho_east(state)
        state = self.gaston_theta(state)
        state = self.gaston_rho_west(state)
        state = self.gaston_iota(state, rc)
        state = self.gaston_chi_sbox(state)

        return state

    def gaston_rho_east(self, state):
        for row in range(GASTON_NROWS):
            self.add_rotate_component(state[row].id, state[row].input_bit_positions, WORD_SIZE, -GASTON_e[row])
            state[row] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state

    def gaston_theta(self, state):
        inputs_id, inputs_pos = get_inputs_parameter([state[i] for i in range(GASTON_NROWS)])
        rotation_amounts = [GASTON_r, GASTON_s, GASTON_u, *GASTON_t]
        self.add_theta_gaston_component(inputs_id, inputs_pos, GASTON_NROWS * WORD_SIZE, rotation_amounts)
        for row in range(GASTON_NROWS):
            state[row] = ComponentState(
                [self.get_current_component_id()], [list(range(row * WORD_SIZE, (row + 1) * WORD_SIZE))]
            )
        return state

    def gaston_rho_west(self, state):
        for row in range(GASTON_NROWS):
            self.add_rotate_component(state[row].id, state[row].input_bit_positions, WORD_SIZE, -GASTON_w[row])
            state[row] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state

    def gaston_iota(self, state, rc):
        self.add_constant_component(WORD_SIZE, rc)
        const = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[0], const])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[0] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state

    def gaston_chi_sbox(self, state):
        state_chi = []
        inputs_id = state[0].id + state[1].id + state[2].id + state[3].id + state[4].id
        output_ids = []
        for k in range(WORD_SIZE):
            inputs_pos = [[k] for _ in range(GASTON_NROWS)]
            self.add_SBOX_component(inputs_id, inputs_pos, GASTON_NROWS, SBOX)
            output_ids = output_ids + [self.get_current_component_id()]

        for i in range(GASTON_NROWS):
            state_chi.append(ComponentState(output_ids, [[i]] * WORD_SIZE))

        return state_chi
