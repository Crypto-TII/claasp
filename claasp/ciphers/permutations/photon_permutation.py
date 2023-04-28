
# ****************************************************************************
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
from claasp.name_mappings import INPUT_PLAINTEXT
from claasp.utils.utils import get_inputs_parameter
from claasp.DTOs.component_state import ComponentState

IRREDUCIBLE_POLYNOMIAL = 0x13
M = [[2, 4, 2, 11, 2, 8, 5, 6],
     [12, 9, 8, 13, 7, 7, 5, 2],
     [4, 4, 13, 13, 9, 4, 13, 9],
     [1, 6, 5, 1, 12, 13, 15, 14],
     [15, 12, 9, 13, 14, 5, 14, 13],
     [9, 14, 5, 15, 4, 12, 9, 6],
     [12, 2, 2, 10, 3, 1, 1, 14],
     [15, 1, 13, 10, 5, 10, 2, 3]]
IC = [0, 1, 3, 7, 15, 14, 12, 8]
PARAMETERS_CONFIGURATION_LIST = [{'t': 256}]
RC = [1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10]
S_BOX = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]


class PhotonPermutation(Cipher):
    """
    Construct an instance of the PhotonPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``t`` -- **integer** (default: `256`)

    EXAMPLES::

        sage: from claasp.ciphers.permutations.photon_permutation import PhotonPermutation
        sage: photon = PhotonPermutation(t=256)
        sage: photon.number_of_rounds
        12

        sage: photon.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, t=256):
        self.cell_bits = 4
        self.d = 8
        self.t = t
        self.state_bit_size = self.cell_bits * self.d * self.d
        number_of_rounds = 12

        super().__init__(family_name="photon",
                         cipher_type="permutation",
                         cipher_inputs=[INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[self.state_bit_size],
                         cipher_output_bit_size=self.state_bit_size)

        # graph presentation initialization
        self.add_round()

        # state initialization
        state = []
        for i in range(self.d * self.d):
            state.append(ComponentState([INPUT_PLAINTEXT], [[k + i * self.cell_bits for k in range(self.cell_bits)]]))

        # round constant setup
        components_rc = []
        for i in range(len(RC)):
            self.add_constant_component(self.cell_bits, RC[i])
            components_rc.append(ComponentState([self.get_current_component_id()], [list(range(self.cell_bits))]))
        components_ic = []
        for i in range(len(IC)):
            self.add_constant_component(self.cell_bits, IC[i])
            components_ic.append(ComponentState([self.get_current_component_id()], [list(range(self.cell_bits))]))

        for round_number in range(number_of_rounds):
            # round function
            state = self.round_function(state, components_rc[round_number], components_ic)

            # round output
            inputs = []
            for i in range(self.d * self.d):
                inputs.append(deepcopy(state[i]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)
                # initial next round element
                self.add_round()

    def round_function(self, state, component_rc, components_ic):
        # AddConstant
        # state[i,0] = state[i,0] xor RC[r] xor IC[i] for i in range(self.d)
        for i in range(self.d):
            inputs_id, inputs_pos = get_inputs_parameter([state[i * self.d], component_rc, components_ic[i]])
            self.add_XOR_component(inputs_id, inputs_pos, self.cell_bits)
            state[i * self.d] = ComponentState([self.get_current_component_id()], [list(range(self.cell_bits))])

        # SubCells
        # state[i,j] = s_box(state[i, j])
        for i in range(self.d * self.d):
            self.add_SBOX_component(state[i].id, state[i].input_bit_positions, self.cell_bits, S_BOX)
            state[i] = ComponentState([self.get_current_component_id()], [list(range(self.cell_bits))])

        # ShiftRows
        # state_new[i,j] = state[i, (j+i)%8) for i,j in range(8)
        state_new = []
        for i in range(self.d):
            for j in range(self.d):
                state_new.append(state[i * self.d + ((j + i) % 8)])
        state = deepcopy(state_new)

        # MixColumnSerials
        # state = M x state
        for i in range(self.d):
            inputs_id, inputs_pos = get_inputs_parameter([state[i + j * self.d] for j in range(self.d)])
            self.add_mix_column_component(inputs_id, inputs_pos, self.cell_bits * self.d,
                                          [M, IRREDUCIBLE_POLYNOMIAL, self.cell_bits])
            for j in range(self.d):
                state[i + j * self.d] = ComponentState([self.get_current_component_id()],
                                                       [[k + j * self.cell_bits for k in range(self.cell_bits)]])

        return state
