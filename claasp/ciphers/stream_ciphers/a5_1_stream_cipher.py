
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
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import get_inputs_parameter
from claasp.name_mappings import INPUT_KEY, INPUT_FRAME

BIT_LENGTH = "BIT_LENGTH"
TAPPED_BITS = "TAPPED_BITS"
CLOCK_BIT = "CLOCK_BIT"
CLOCK_POLYNOMIAL = "CLOCK_POLYNOMIAL"

REGISTERS = [
    {BIT_LENGTH: 19,
     TAPPED_BITS: [[0], [1], [2], [5]],
     #CLOCK_BIT: 10,
     CLOCK_POLYNOMIAL: [[10, 30], [30, 53], [10, 53], [10], []]},
    {BIT_LENGTH: 22,
     # TAPPED_BITS: [[0], [1]],
     TAPPED_BITS: [[19], [20]],
     #CLOCK_BIT: 11, 30
     CLOCK_POLYNOMIAL: [[10, 30], [30, 53], [10, 53], [30], []]},
    {BIT_LENGTH: 23,
     #TAPPED_BITS: [[0], [1], [2], [15]],
     TAPPED_BITS: [[41], [42], [43], [56]],
     #CLOCK_BIT: 12, 53
     CLOCK_POLYNOMIAL: [[10, 30], [30, 53], [10, 53], [53], []]},
]


PARAMETERS_CONFIGURATION_LIST = [{'key_bit_size': 64, 'frame_bit_size': 22,
                                  'number_of_normal_clocks_at_initialization': 100,
                                  'number_of_rounds': 228}]


class A51StreamCipher(Cipher):
    """
    Construct an instance of the A51StreamCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
        - ``number_of_rounds`` -- **integer** (default: `640`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.permutations.tinyjambu_32bits_word_permutation import TinyJambuFSRWordBasedPermutation
        sage: tinyjambu = TinyJambuFSRWordBasedPermutation()
        sage: tinyjambu.number_of_rounds
        20

        sage: tinyjambu.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, key_bit_size=64, frame_bit_size=22, number_of_normal_clocks_at_initialization=100,
                 number_of_rounds=228):

        super().__init__(family_name="a51",
                         cipher_type="stream_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_FRAME],
                         cipher_inputs_bit_size=[key_bit_size, frame_bit_size],
                         cipher_output_bit_size=number_of_rounds)

        # registers initialization
        regs_size = 0
        regs_output_bit = []
        for item in REGISTERS:
            regs_size += item[BIT_LENGTH]
            regs_output_bit.append(regs_size-1)

        regs = self.regs_initialization(key_bit_size=key_bit_size, frame_bit_size=frame_bit_size,
                                        number_of_normal_clocks_at_initialization=number_of_normal_clocks_at_initialization,
                                        regs_size=regs_size)

        fsr_description = [[[REGISTERS[i][BIT_LENGTH], REGISTERS[i][TAPPED_BITS],
                             REGISTERS[i][CLOCK_POLYNOMIAL]] for i in range(len(REGISTERS))], 1, 1]
        cipher_output=[]
        for r in range(number_of_rounds):
            regs = self.round_function(regs=regs, regs_size=regs_size, fsr_description=fsr_description)
            regs_xor_output = []
            for i in range(len(REGISTERS)):
                regs_xor_output.append(ComponentState(regs.id, [[regs_output_bit[i]]]))
            inputs_id, inputs_pos = get_inputs_parameter(regs_xor_output)
            self.add_XOR_component(inputs_id, inputs_pos, 1)
            cipher_output.append(ComponentState([self.get_current_component_id()], [[0]]))

        inputs_id, inputs_pos = get_inputs_parameter(cipher_output)
        self.add_cipher_output_component(inputs_id, inputs_pos, number_of_rounds)

    def regs_initialization(self, key_bit_size, frame_bit_size, number_of_normal_clocks_at_initialization, regs_size):
        # registers initialization
        self.add_round()
        constant_0 = []
        for i in range(len(REGISTERS)):
            self.add_constant_component(REGISTERS[i][BIT_LENGTH] - 1, 0)
            constant_0.append(ComponentState([self.get_current_component_id()],
                                           [[i for i in range(REGISTERS[i][BIT_LENGTH] - 1)]]))

        self.add_constant_component(regs_size, 0)
        regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

        fsr_description = [[[REGISTERS[i][BIT_LENGTH], REGISTERS[i][TAPPED_BITS], []] for i in range(len(REGISTERS))],
                           1, 1]
        for i in range(key_bit_size):
            inputs = [regs]
            for j in range(len(REGISTERS)):
                inputs.append(constant_0[j])
                inputs.append(ComponentState([INPUT_KEY], [[j]]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_XOR_component(inputs_id, inputs_pos, regs_size)
            regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

            self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
            regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

        for i in range(frame_bit_size):
            inputs = [regs]
            for j in range(len(REGISTERS)):
                inputs.append(constant_0[j])
                inputs.append(ComponentState([INPUT_FRAME], [[j]]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_XOR_component(inputs_id, inputs_pos, regs_size)
            regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

            self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
            regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

        fsr_description = [[[REGISTERS[i][BIT_LENGTH], REGISTERS[i][TAPPED_BITS],
                             REGISTERS[i][CLOCK_POLYNOMIAL]] for i in range(len(REGISTERS))], 1,
                           number_of_normal_clocks_at_initialization]
        self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
        regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

        return regs

    def round_function(self, regs, regs_size, fsr_description):
        self.add_round()
        self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
        regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

        return regs
