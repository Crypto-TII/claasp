
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
    {BIT_LENGTH: 128,
     TAPPED_BITS: [[0], [26], [56], [91], [96], [128],
                   [3, 67], [11, 13], [17, 18], [27, 59], [40, 48],
                   [61, 65], [68, 84],
                   [22, 24, 25], [70, 78, 82], [88, 92, 93, 95] ]},
    {BIT_LENGTH: 128,
     TAPPED_BITS: [[128], [135], [166], [198], [209], [224]]},
]

PRE_OUTPUT_GENERATOR = [
    {BIT_LENGTH: 256,
     TAPPED_BITS: [[2], [15], [36], [45], [64], [73], [89], [221],
                   [12, 136], [141, 148], [95, 170], [188, 207],
                   [12, 95, 222]]}
]

NONCE_PADDING = 0xfffffffe

PARAMETERS_CONFIGURATION_LIST = [{'key_bit_size': 128, 'frame_bit_size': 96,
                                  'number_of_normal_clocks_at_initialization': 320,
                                  'number_of_rounds': 228}]


class Grain128StreamCipher(Cipher):
    """
    Construct an instance of the Grain128StreamCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
        - ``number_of_rounds`` -- **integer** (default: `640`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.stream_ciphers.grain128_stream_cipher import Grain128StreamCipher
        sage: grain128 = Grain128StreamCipher()
        sage: grain128.number_of_rounds
        229

        sage: grain128.component_from(0, 0).id
        'constant_0_0'

        sage: grain128.component_from(1, 0).id
        'fsr_1_0'

        sage: key = 0x48c4a2e691d5b3f7
        sage: frame = 0b0010110010000000000000
        sage: keystream = 0x534eaa582fe8151ab6e1855a728c093f4d68d757ed949b4cbe41b7c6b
        sage: a51.evaluate([key, frame]) == keystream
        True

    """

    def __init__(self, key_bit_size=128, nonce_bit_size=96, number_of_normal_clocks_at_initialization=100,
                 number_of_rounds=228):

        super().__init__(family_name="a51",
                         cipher_type="stream_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_FRAME],
                         cipher_inputs_bit_size=[key_bit_size, nonce_bit_size],
                         cipher_output_bit_size=number_of_rounds)

        # registers initialization
        regs_size = 0
        regs_output_bit = [0]
        for i in range(len(REGISTERS)-1):
            regs_size += REGISTERS[i][BIT_LENGTH]
            regs_output_bit.append(regs_size)
        regs_size += REGISTERS[-1][BIT_LENGTH]

        regs = self.regs_initialization(key_bit_size=key_bit_size, nonce_bit_size=nonce_bit_size,
                                        number_of_normal_clocks_at_initialization=number_of_normal_clocks_at_initialization,
                                        regs_size=regs_size)

        # self.add_cipher_output_component(regs.id, [[i for i in range(regs_size)]], regs_size)

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

    def regs_initialization(self, key_bit_size, nonce_bit_size, number_of_normal_clocks_at_initialization, regs_size):
        # registers initialization
        self.add_round()
        constant_0 = []
        for i in range(len(REGISTERS)):
            self.add_constant_component(REGISTERS[i][BIT_LENGTH] - 1, 0)
            constant_0.append(ComponentState([self.get_current_component_id()],
                                           [[i for i in range(REGISTERS[i][BIT_LENGTH] - 1)]]))

        self.add_constant_component(regs_size, 0)
        regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

        # load key
        fsr_description = [[[REGISTERS[i][BIT_LENGTH], REGISTERS[i][TAPPED_BITS]] for i in range(len(REGISTERS))], 1]
        for i in range(key_bit_size):
            self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
            regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

            inputs = [regs]
            for j in range(len(REGISTERS)):
                inputs.append(constant_0[j])
                inputs.append(ComponentState([INPUT_KEY], [[i]]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_XOR_component(inputs_id, inputs_pos, regs_size)
            regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

        # load frame
        for i in range(nonce_bit_size):
            self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
            regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

            inputs = [regs]
            for j in range(len(REGISTERS)):
                inputs.append(constant_0[j])
                inputs.append(ComponentState([INPUT_FRAME], [[i]]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_XOR_component(inputs_id, inputs_pos, regs_size)
            regs = ComponentState([self.get_current_component_id()], [[i for i in range(regs_size)]])

        # normal clocked without output
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
