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

SBOX_CELL_SIZE = 8
ICOUNTER_SIZE = 7
ICOUNTER_IV_160 = 0x75
ICOUNTER_IV_176 = 0x45
PARAMETERS_CONFIGURATION_LIST = [
    {"state_bit_size": 160, "number_of_rounds": 80},
    {"state_bit_size": 176, "number_of_rounds": 90},
]
# fmt: off
S_BOX = [
    0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5, 0xe9, 0xec, 0xe3, 0xe6,
    0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda, 0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6,
    0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6,
    0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c, 0x03, 0x06,
    0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23, 0x26,
    0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16,
    0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46,
    0xfe, 0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6,
    0x7e, 0x7d, 0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76,
    0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5, 0xa9, 0xac, 0xa3, 0xa6,
    0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f, 0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86,
    0x5e, 0x5d, 0x5b, 0x50, 0x52, 0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56,
    0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96,
    0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6,
    0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36,
    0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67, 0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66,
]
PERMUTE_160 = [
    0, 40, 80, 120, 1, 41, 81, 121, 2, 42, 82, 122, 3, 43, 83, 123, 4, 44, 84, 124, 5, 45, 85, 125,
    6, 46, 86, 126, 7, 47, 87, 127, 8, 48, 88, 128, 9, 49, 89, 129, 10, 50, 90, 130, 11, 51, 91, 131,
    12, 52, 92, 132, 13, 53, 93, 133, 14, 54, 94, 134, 15, 55, 95, 135, 16, 56, 96, 136, 17, 57, 97, 137,
    18, 58, 98, 138, 19, 59, 99, 139, 20, 60, 100, 140, 21, 61, 101, 141, 22, 62, 102, 142, 23, 63, 103, 143,
    24, 64, 104, 144, 25, 65, 105, 145, 26, 66, 106, 146, 27, 67, 107, 147, 28, 68, 108, 148, 29, 69, 109, 149,
    30, 70, 110, 150, 31, 71, 111, 151, 32, 72, 112, 152, 33, 73, 113, 153, 34, 74, 114, 154, 35, 75, 115, 155,
    36, 76, 116, 156, 37, 77, 117, 157, 38, 78, 118, 158, 39, 79, 119, 159
]
PERMUTE_176 = [
    0, 44, 88, 132, 1, 45, 89, 133, 2, 46, 90, 134, 3, 47, 91, 135, 4, 48, 92, 136, 5, 49, 93, 137,
    6, 50, 94, 138, 7, 51, 95, 139, 8, 52, 96, 140, 9, 53, 97, 141, 10, 54, 98, 142, 11, 55, 99, 143,
    12, 56, 100, 144, 13, 57, 101, 145, 14, 58, 102, 146, 15, 59, 103, 147, 16, 60, 104, 148, 17, 61, 105, 149,
    18, 62, 106, 150, 19, 63, 107, 151, 20, 64, 108, 152, 21, 65, 109, 153, 22, 66, 110, 154, 23, 67, 111, 155,
    24, 68, 112, 156, 25, 69, 113, 157, 26, 70, 114, 158, 27, 71, 115, 159, 28, 72, 116, 160, 29, 73, 117, 161,
    30, 74, 118, 162, 31, 75, 119, 163, 32, 76, 120, 164, 33, 77, 121, 165, 34, 78, 122, 166, 35, 79, 123, 167,
    36, 80, 124, 168, 37, 81, 125, 169, 38, 82, 126, 170, 39, 83, 127, 171, 40, 84, 128, 172, 41, 85, 129, 173,
    42, 86, 130, 174, 43, 87, 131, 175
]
# fmt: on


class SpongentPiFSRPermutation(Cipher):
    """
    Construct an instance of the SpongentPiFSRPermutation class with FSR component.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``state_bit_size`` -- **integer** (default: `160`)
        - ``number_of_rounds`` -- **integer** (default: `80`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.spongent_pi_fsr_permutation import SpongentPiFSRPermutation
        sage: spongentpi = SpongentPiFSRPermutation(state_bit_size=160, number_of_rounds=80)
        sage: spongentpi.number_of_rounds
        80

        sage: spongentpi.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, state_bit_size=160, number_of_rounds=80):
        self.state_bit_size = state_bit_size
        self.state_len = int(self.state_bit_size / SBOX_CELL_SIZE)
        if self.state_bit_size == 160:
            self.icounter_iv = ICOUNTER_IV_160
            self.permute = PERMUTE_160
        elif self.state_bit_size == 176:
            self.icounter_iv = ICOUNTER_IV_176
            self.permute = PERMUTE_176
        else:
            print("The parameter state_bit_size = ", str(self.state_bit_size), " is not implemented.")
            return

        super().__init__(
            family_name="spongent_pi_fsr",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        state = []
        for i in range(self.state_len):
            state.append(ComponentState([INPUT_PLAINTEXT], [[k + i * SBOX_CELL_SIZE for k in range(SBOX_CELL_SIZE)]]))

        # initial current round element
        self.add_round()
        # constant 0
        self.add_constant_component(1, 0)
        const_0 = ComponentState([self.get_current_component_id()], [[0]])
        # icounter initialization
        self.add_constant_component(ICOUNTER_SIZE, self.icounter_iv)
        icounter = ComponentState([self.get_current_component_id()], [list(range(ICOUNTER_SIZE))])

        for round_number in range(number_of_rounds):
            # round function
            state = self.round_function(state, icounter, const_0)

            # round output
            inputs = []
            for i in range(self.state_len):
                inputs.append(state[i])
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)
                # next round initialization
                self.add_round()
                # update icounter
                icounter = self.icounter_update(icounter)

    def icounter_update(self, icounter):
        # x0||x1||x2||x3||x4||x5||x6 -> x1||x2||x3||x4||x5||x6||x0 xor x1
        # fsr_polynomial = x0+x1+1 = x^7+x^6+1
        self.add_FSR_component(
            icounter.id, icounter.input_bit_positions, ICOUNTER_SIZE, [[[ICOUNTER_SIZE, [[0], [1]], []]], 1, 1]
        )
        icounter = ComponentState([self.get_current_component_id()], [list(range(ICOUNTER_SIZE))])

        return icounter

    def round_function(self, state, icounter, const_0):
        # state[len-1] = state[len-1] xor 0|icounter
        inputs_id, inputs_pos = get_inputs_parameter([state[self.state_len - 1], const_0, icounter])
        self.add_XOR_component(inputs_id, inputs_pos, SBOX_CELL_SIZE)
        state[self.state_len - 1] = ComponentState([self.get_current_component_id()], [list(range(SBOX_CELL_SIZE))])

        # state[0] = state[0] xor reverse(0|icounter)
        self.add_reverse_component(icounter.id, icounter.input_bit_positions, ICOUNTER_SIZE)
        reverse_icounter = ComponentState([self.get_current_component_id()], [list(range(SBOX_CELL_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[0], reverse_icounter, const_0])
        self.add_XOR_component(inputs_id, inputs_pos, SBOX_CELL_SIZE)
        state[0] = ComponentState([self.get_current_component_id()], [list(range(SBOX_CELL_SIZE))])

        # state[i] = sbox(state[i])
        for i in range(self.state_len):
            self.add_SBOX_component(state[i].id, state[i].input_bit_positions, SBOX_CELL_SIZE, S_BOX)
            state[i] = ComponentState([self.get_current_component_id()], [list(range(SBOX_CELL_SIZE))])

        # state[j] = permute(state[j])
        inputs = []
        for i in range(self.state_len):
            inputs.append(state[i])
        inputs_id, inputs_pos = get_inputs_parameter(inputs)
        self.add_permutation_component(inputs_id, inputs_pos, self.state_bit_size, self.permute)
        for i in range(self.state_len):
            state[i] = ComponentState(
                [self.get_current_component_id()], [[k + i * SBOX_CELL_SIZE for k in range(SBOX_CELL_SIZE)]]
            )

        return state
