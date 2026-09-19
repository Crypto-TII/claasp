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

from claasp_next.graph.bit_builder import BitGraphPrimitive
from claasp_next.graph.bit_builder import BitState
from claasp_next.primitive_inputs import INPUT_FRAME, INPUT_KEY, STREAM_CIPHER
from claasp_next.graph.bit_builder import get_inputs_parameter

BIT_LENGTH = "BIT_LENGTH"
TAPPED_BITS = "TAPPED_BITS"
CLOCK_BIT = "CLOCK_BIT"
CLOCK_POLYNOMIAL = "CLOCK_POLYNOMIAL"

REGISTERS = [
    {BIT_LENGTH: 19, TAPPED_BITS: [[0], [1], [2], [5]], CLOCK_POLYNOMIAL: [[10, 30], [30, 53], [10, 53], [10], []]},
    {BIT_LENGTH: 22, TAPPED_BITS: [[19], [20]], CLOCK_POLYNOMIAL: [[10, 30], [30, 53], [10, 53], [30], []]},
    {BIT_LENGTH: 23, TAPPED_BITS: [[41], [42], [43], [56]], CLOCK_POLYNOMIAL: [[10, 30], [30, 53], [10, 53], [53], []]},
]


PARAMETERS_CONFIGURATION_LIST = [
    {
        "key_bit_size": 64,
        "frame_bit_size": 22,
        "number_of_normal_clocks_at_initialization": 100,
        "number_of_rounds": 228,
    }
]


class A51(BitGraphPrimitive):
    """
    Construct an instance of the A51 class.

    This class is used to store compact representations of a primitive, used to generate the corresponding primitive.

    INPUT:

        - ``key_bit_size`` -- **integer** (default: `64`); primitive key bit size of the primitive
        - ``number_of_rounds`` -- **integer** (default: `228`); number of rounds of the primitive

    EXAMPLES::

        >>> primitive = A51()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self, key_bit_size=64, frame_bit_size=22, number_of_normal_clocks_at_initialization=100, number_of_rounds=228
    ):
        super().__init__(
            family_name="a51",
            primitive_type=STREAM_CIPHER,
            primitive_inputs=[INPUT_KEY, INPUT_FRAME],
            primitive_inputs_bit_size=[key_bit_size, frame_bit_size],
            primitive_output_bit_size=number_of_rounds,
        )

        # registers initialization
        regs_size = 0
        regs_output_bit = [0]
        for register in REGISTERS[:-1]:
            regs_size += register[BIT_LENGTH]
            regs_output_bit.append(regs_size)
        regs_size += REGISTERS[-1][BIT_LENGTH]

        regs = self.regs_initialization(
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
        primitive_output = []
        for _ in range(number_of_rounds):
            regs = self.round_function(regs=regs, regs_size=regs_size, fsr_description=fsr_description)
            regs_xor_output = []
            for i in range(len(REGISTERS)):
                regs_xor_output.append(BitState(regs.id, [[regs_output_bit[i]]]))
            inputs_id, inputs_pos = get_inputs_parameter(regs_xor_output)
            self.add_xor_component(inputs_id, inputs_pos, 1)
            primitive_output.append(BitState([self.get_current_component_id()], [[0]]))

        inputs_id, inputs_pos = get_inputs_parameter(primitive_output)
        self.add_primitive_output_component(inputs_id, inputs_pos, number_of_rounds)

    def regs_initialization(self, key_bit_size, frame_bit_size, number_of_normal_clocks_at_initialization, regs_size):
        # registers initialization
        """Build the regs initialization stage in this primitive's typed operation graph."""
        self.add_round()
        constant_0 = []
        for register in REGISTERS:
            self.add_constant_component(register[BIT_LENGTH] - 1, 0)
            constant_0.append(
                BitState([self.get_current_component_id()], [list(range(register[BIT_LENGTH] - 1))])
            )

        self.add_constant_component(regs_size, 0)
        regs = BitState([self.get_current_component_id()], [list(range(regs_size))])

        # load key
        fsr_description = [[[register[BIT_LENGTH], register[TAPPED_BITS]] for register in REGISTERS], 1]
        for i in range(key_bit_size):
            self.add_fsr_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
            regs = BitState([self.get_current_component_id()], [list(range(regs_size))])

            inputs = [regs]
            for j in range(len(REGISTERS)):
                inputs.append(constant_0[j])
                inputs.append(BitState([INPUT_KEY], [[i]]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_xor_component(inputs_id, inputs_pos, regs_size)
            regs = BitState([self.get_current_component_id()], [list(range(regs_size))])

        # load frame
        for i in range(frame_bit_size):
            self.add_fsr_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
            regs = BitState([self.get_current_component_id()], [list(range(regs_size))])

            inputs = [regs]
            for j in range(len(REGISTERS)):
                inputs.append(constant_0[j])
                inputs.append(BitState([INPUT_FRAME], [[i]]))
            inputs_id, inputs_pos = get_inputs_parameter(inputs)
            self.add_xor_component(inputs_id, inputs_pos, regs_size)
            regs = BitState([self.get_current_component_id()], [list(range(regs_size))])

        # normal clocked without output
        fsr_description = [
            [[register[BIT_LENGTH], register[TAPPED_BITS], register[CLOCK_POLYNOMIAL]] for register in REGISTERS],
            1,
            number_of_normal_clocks_at_initialization,
        ]
        self.add_fsr_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
        regs = BitState([self.get_current_component_id()], [list(range(regs_size))])

        return regs

    def round_function(self, regs, regs_size, fsr_description):
        """Build the round function stage in this primitive's typed operation graph."""
        self.add_round()
        self.add_fsr_component(regs.id, regs.input_bit_positions, regs_size, fsr_description)
        regs = BitState([self.get_current_component_id()], [list(range(regs_size))])

        return regs
