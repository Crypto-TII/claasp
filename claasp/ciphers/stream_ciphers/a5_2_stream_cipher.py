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

MASK_AFTER_FRAME_SETUP = 0b000100000000000000000000100000000000000000000100000000000000000000000000010000000


REGISTERS = [
    {BIT_LENGTH: 19, TAPPED_BITS: [[0], [1], [2], [5]], CLOCK_POLYNOMIAL: [[70, 73], [70, 77], [73, 77], [70], []]},
    {BIT_LENGTH: 22, TAPPED_BITS: [[19], [20]], CLOCK_POLYNOMIAL: [[70, 73], [70, 77], [73, 77], [77], []]},
    {BIT_LENGTH: 23, TAPPED_BITS: [[41], [42], [43], [56]], CLOCK_POLYNOMIAL: [[70, 73], [70, 77], [73, 77], [73], []]},
    {BIT_LENGTH: 17, TAPPED_BITS: [[64], [69]], CLOCK_POLYNOMIAL: None},
]


PARAMETERS_CONFIGURATION_LIST = [
    {
        "key_bit_size": 64,
        "frame_bit_size": 22,
        "number_of_normal_clocks_at_initialization": 100,
        "number_of_rounds": 228,
    }
]


class A52StreamCipher(Cipher):
    """
    Construct an instance of the A52StreamCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

        - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
        - ``number_of_rounds`` -- **integer** (default: `640`); number of rounds of the cipher

    EXAMPLES::

        sage: from claasp.ciphers.stream_ciphers.a5_2_stream_cipher import A52StreamCipher
        sage: a52 = A52StreamCipher()
        sage: a52.number_of_rounds
        229

        sage: a52.component_from(0, 0).id
        'constant_0_0'

        sage: a52.component_from(1, 0).id
        'fsr_1_0'

        sage: key = 0x003fffffffffffff
        sage: frame = 0b1000010000000000000000
        sage: keystream = 0xf4512cac13593764460b722dadd51200350ca385a853735ee5c889944
        sage: a52.evaluate([key, frame]) == keystream
        True

    """

    def __init__(
        self, key_bit_size=64, frame_bit_size=22, number_of_normal_clocks_at_initialization=100, number_of_rounds=228
    ):
        super().__init__(
            family_name="a52",
            cipher_type="stream_cipher",
            cipher_inputs=[INPUT_KEY, INPUT_FRAME],
            cipher_inputs_bit_size=[key_bit_size, frame_bit_size],
            cipher_output_bit_size=number_of_rounds,
        )

        # registers initialization
        regs_size = sum(register[BIT_LENGTH] for register in REGISTERS)
        regs = self._regs_initialization(
            key_bit_size=key_bit_size,
            frame_bit_size=frame_bit_size,
            number_of_normal_clocks_at_initialization=number_of_normal_clocks_at_initialization,
            regs_size=regs_size,
        )

        fsr_description = [
            [[register[BIT_LENGTH], register[TAPPED_BITS], register[CLOCK_POLYNOMIAL]] for register in REGISTERS],
            1,
            1,
        ]
        cipher_output = []
        for _ in range(number_of_rounds):
            regs_xor_output = []
            regs_xor_bit = [0, 3, 6, 19, 27, 31, 41, 45, 47]
            for i in regs_xor_bit:
                regs_xor_output.append(ComponentState(regs.id, [[i]]))
            regs_and_bit = [[3, 4, 6], [24, 27, 31], [45, 47, 50]]
            for k in regs_and_bit:
                for i in range(len(k)):
                    for j in range(i + 1, len(k)):
                        self.add_AND_component(regs.id, [[k[i], k[j]]], 1)
                        regs_xor_output.append(ComponentState([self.get_current_component_id()], [[0]]))

            inputs_id, inputs_pos = get_inputs_parameter(regs_xor_output)
            self.add_XOR_component(inputs_id, inputs_pos, 1)
            cipher_output.append(ComponentState([self.get_current_component_id()], [[0]]))

            regs = self._round_function(regs=regs, regs_size=regs_size, fsr_description=fsr_description)

        inputs_id, inputs_pos = get_inputs_parameter(cipher_output)
        self.add_cipher_output_component(inputs_id, inputs_pos, number_of_rounds)

    def _regs_initialization(self, key_bit_size, frame_bit_size, number_of_normal_clocks_at_initialization, regs_size):
        # registers initialization
        self.add_round()
        constant_0 = []
        for register in REGISTERS:
            self.add_constant_component(register[BIT_LENGTH] - 1, 0)
            constant_0.append(
                ComponentState([self.get_current_component_id()], [list(range(register[BIT_LENGTH] - 1))])
            )

        self.add_constant_component(regs_size, 0)
        regs = ComponentState([self.get_current_component_id()], [list(range(regs_size))])

        # load key
        fsr_description = [[[register[BIT_LENGTH], register[TAPPED_BITS]] for register in REGISTERS], 1]
        for i in range(key_bit_size):
            self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
            regs = ComponentState([self.get_current_component_id()], [list(range(regs_size))])

            inputs = [regs]
            for j in range(len(REGISTERS)):
                inputs.append(constant_0[j])
                inputs.append(ComponentState([INPUT_KEY], [[i]]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_XOR_component(inputs_id, inputs_pos, regs_size)
            regs = ComponentState([self.get_current_component_id()], [list(range(regs_size))])

        # load frame
        for i in range(frame_bit_size):
            self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
            regs = ComponentState([self.get_current_component_id()], [list(range(regs_size))])

            inputs = [regs]
            for j in range(len(REGISTERS)):
                inputs.append(constant_0[j])
                inputs.append(ComponentState([INPUT_FRAME], [[i]]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_XOR_component(inputs_id, inputs_pos, regs_size)
            regs = ComponentState([self.get_current_component_id()], [list(range(regs_size))])
        # For A5/2, somebits is fixed to 1 after frame is loaded
        self.add_constant_component(regs_size, MASK_AFTER_FRAME_SETUP)
        mask = ComponentState([self.get_current_component_id()], [list(range(regs_size))])
        inputs_id, inputs_pos = get_inputs_parameter([regs, mask])
        self.add_OR_component(inputs_id, inputs_pos, regs_size)
        regs = ComponentState([self.get_current_component_id()], [list(range(regs_size))])

        # normal clocked without output
        fsr_description = [
            [[register[BIT_LENGTH], register[TAPPED_BITS], register[CLOCK_POLYNOMIAL]] for register in REGISTERS],
            1,
            number_of_normal_clocks_at_initialization,
        ]
        self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
        regs = ComponentState([self.get_current_component_id()], [list(range(regs_size))])

        return regs

    def _round_function(self, regs, regs_size, fsr_description):
        self.add_round()
        self.add_FSR_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
        regs = ComponentState([self.get_current_component_id()], [list(range(regs_size))])

        return regs
