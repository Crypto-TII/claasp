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
from claasp.name_mappings import INPUT_PLAINTEXT
from claasp.utils.utils import get_inputs_parameter
from claasp.DTOs.component_state import ComponentState

GASTON_NROWS = 5
WORD_SIZE = 64

# parameters for theta
GASTON_t = [25, 32, 52, 60, 63]
# GASTON_t0 = 25
# GASTON_t1 = 32
# GASTON_t2 = 52
# GASTON_t3 = 60
# GASTON_t4 = 63

GASTON_r = 1
GASTON_s = 18
GASTON_u = 23

# rho-east rotation offsets
GASTON_e = [0, 60, 22, 27, 4]
# GASTON_e0 = 0
# GASTON_e1 = 60
# GASTON_e2 = 22
# GASTON_e3 = 27
# GASTON_e4 = 4

# rho-west rotation offsets
GASTON_w = [0, 56, 31, 46, 43]
# GASTON_w0 = 0
# GASTON_w1 = 56
# GASTON_w2 = 31
# GASTON_w3 = 46
# GASTON_w4 = 43

# gaston round constant
gaston_rc = [
    0x00000000000000F0, 0x00000000000000E1, 0x00000000000000D2,
    0x00000000000000C3, 0x00000000000000B4, 0x00000000000000A5,
    0x0000000000000096, 0x0000000000000087, 0x0000000000000078,
    0x0000000000000069, 0x000000000000005A, 0x000000000000004B
]

PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 12}]


class GastonPermutation(Cipher):
    """
    Construct an instance of the Gaston Permutation class.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.gaston_permutation import GastonPermutation
        sage: gaston = GastonPermutation(number_of_rounds=12)
        sage: plaintext = 0x0
        sage: ciphertext = 0x88B326096BEBC6356CA8FB64BC5CE6CAF1CE3840D819071354D70067438689B5F17FE863F958F32B
        sage: print(gaston.evaluate([plaintext]))==ciphertext)
        True

        sage: plaintext=0x1F4AD9906DA6A2544B84D7F83F2BDDFA468A0853578A00E36C05A0506DF7F66E4EFB22112453C964
        sage: ciphertext=0x1BA89B5B5C4583B622135709AE53417D9847B975E9EC9F3DCE042DF2A402591D563EC68FC30307EA
        sage: print(gaston.evaluate([plaintext])==ciphertext)
        True

        sage: plaintext=0xFFFFFFFFFFFFFFFF0123456789ABCDEFFEDCBA9876543210AAAAAAAAAAAAAAAA0101010101010101
        sage: ciphertext=0x3117D51B14937067338F17F773C13F79DFB86E0868D252AB0D461D35EB863DE708BCE3E354C7231A
        sage: print(gaston.evaluate([plaintext])==ciphertext)
        True

        sage: gaston.number_of_rounds
        12
        sage: gaston.component_from(0, 0).id
        'rot_0_0'
    """

    def __init__(self, number_of_rounds=12):
        self.state_bit_size = GASTON_NROWS * WORD_SIZE

        super().__init__(family_name='gaston',
                         cipher_type="permutation",
                         cipher_inputs=[INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[self.state_bit_size],
                         cipher_output_bit_size=self.state_bit_size)

        # gaston state initialization
        state = []
        for row in range(GASTON_NROWS):
            p = ComponentState([INPUT_PLAINTEXT], [[i + row * WORD_SIZE for i in range(WORD_SIZE)]])
            state.append(p)

        for round_number in range(12 - number_of_rounds, 12):
            self.add_round()
            # gaston round function
            state = self.gaston_round_function(state, gaston_rc[round_number])
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
        state = self.gaston_chi(state)

        return state

    def gaston_rho_east(self, state):
        for row in range(GASTON_NROWS):
            self.add_rotate_component(state[row].id, state[row].input_bit_positions, WORD_SIZE, -GASTON_e[row])
            state[row] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state

    def gaston_theta(self, state):
        inputs_id, inputs_pos = get_inputs_parameter([state[i] for i in range(GASTON_NROWS)])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        P = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        self.add_rotate_component(P.id, P.input_bit_positions, WORD_SIZE, -GASTON_r)
        P_rot = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([P, P_rot])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        P = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        # column parity P

        Q_rows = []
        for i in range(GASTON_NROWS):
            self.add_rotate_component(state[i].id, state[i].input_bit_positions, WORD_SIZE, -GASTON_t[i])
            q = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            Q_rows.append(q)

        inputs_id, inputs_pos = get_inputs_parameter([Q_rows[i] for i in range(GASTON_NROWS)])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        Q = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        self.add_rotate_component(Q.id, Q.input_bit_positions, WORD_SIZE, -GASTON_s)
        Q_rot = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([Q, Q_rot])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        Q = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        # column parity Q

        inputs_id, inputs_pos = get_inputs_parameter([P, Q])
        self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        P = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        self.add_rotate_component(P.id, P.input_bit_positions, WORD_SIZE, -GASTON_u)
        P = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        for row in range(GASTON_NROWS):
            inputs_id, inputs_pos = get_inputs_parameter([state[row], P])
            self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
            state[row] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

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

    def gaston_chi(self, state):
        not_comp = []
        for row in range(GASTON_NROWS):
            self.add_NOT_component(state[row].id, state[row].input_bit_positions, WORD_SIZE)
            n = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            not_comp.append(n)

        and_comp = []
        for row in range(GASTON_NROWS):
            inputs_id, inputs_pos = get_inputs_parameter(
                [state[(row + 2) % GASTON_NROWS], not_comp[(row + 1) % GASTON_NROWS]])
            self.add_AND_component(inputs_id, inputs_pos, WORD_SIZE)
            a = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            and_comp.append(a)

        for row in range(GASTON_NROWS):
            inputs_id, inputs_pos = get_inputs_parameter([state[row], and_comp[row]])
            self.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
            state[row] = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state
