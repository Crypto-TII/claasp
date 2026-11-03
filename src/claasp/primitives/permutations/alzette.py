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


from claasp.graph.bit_builder import BitGraphPrimitive, BitState, get_inputs_parameter
from claasp.primitive_inputs import INPUT_PLAINTEXT, PERMUTATION

WORD_SIZE = 32

# Rotation pairs (ry, rx) for the four Alzette sub-rounds.
# Sub-round i performs: x += ROT(y, ry), y ^= ROT(x, rx), x ^= c.
# Source: Algorithm 1 and Appendix C/D of [BBBGPUV2020]_.
ALZETTE_ROTATIONS = [(31, 24), (17, 17), (0, 31), (24, 16)]

# Round constants used in the SPARKLE permutation family (and recommended
# by the Alzette designers for instantiations).  Indexed c0 .. c7.
SPARKLE_CONSTANTS = [
    0xB7E15162,
    0xBF715880,
    0x38B4DA56,
    0x324E7738,
    0xBB1185EB,
    0x4F7C7B57,
    0xCFBFA1C8,
    0xC2B3293D,
]

PARAMETERS_CONFIGURATION_LIST = [{"round_constant": SPARKLE_CONSTANTS[0]}]


class Alzette(BitGraphPrimitive):
    """Alzette primitive represented by a typed bit graph.

    The construction preserves the legacy round and key-schedule conventions.

    EXAMPLES::

        >>> from claasp.primitives import Alzette
        >>> hex(Alzette().evaluate(0))
        '0x44dd4de9e5581f2d'
    """

    def __init__(self, round_constant=SPARKLE_CONSTANTS[0]):
        round_constant = int(round_constant) & ((1 << WORD_SIZE) - 1)

        self.word_size = WORD_SIZE
        self.state_bit_size = 2 * WORD_SIZE
        super().__init__(
            family_name="alzette",
            primitive_type=PERMUTATION,
            primitive_inputs=[INPUT_PLAINTEXT],
            primitive_inputs_bit_size=[self.state_bit_size],
            primitive_output_bit_size=self.state_bit_size,
        )

        # Bake the round constant into a constant component that is reused
        # across all sub-rounds.  It is created inside the first round so
        # that number_of_rounds equals the number of Alzette sub-rounds (4).
        self._builder.add_round()
        self.add_constant_component(WORD_SIZE, round_constant)
        ci = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # Initial state: x occupies bits 0..31, y occupies bits 32..63.
        state_x = BitState([INPUT_PLAINTEXT], [list(range(WORD_SIZE))])
        state_y = BitState([INPUT_PLAINTEXT], [list(range(WORD_SIZE, 2 * WORD_SIZE))])

        for sub_round_idx, (ry, rx) in enumerate(ALZETTE_ROTATIONS):
            state_x, state_y = self._alzette_sub_round(state_x, state_y, ci, ry, rx)

            inputs_id, inputs_pos = get_inputs_parameter([state_x, state_y])
            if sub_round_idx == len(ALZETTE_ROTATIONS) - 1:
                self.add_primitive_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)
                self._builder.add_round()

    def _alzette_sub_round(self, state_x, state_y, ci, ry, rx):
        """Perform one Alzette sub-round: x+=ROT(y,ry), y^=ROT(x,rx), x^=c."""
        # x <- x + ROT(y, ry)
        if ry == 0:
            # ROT(y, 0) is the identity — skip the rotate component.
            inputs_id, inputs_pos = get_inputs_parameter([state_x, state_y])
        else:
            self.add_rotate_component(state_y.id, state_y.input_bit_positions, WORD_SIZE, ry)
            rot_y = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            inputs_id, inputs_pos = get_inputs_parameter([state_x, rot_y])
        self.add_modadd_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # y <- y XOR ROT(x, rx)
        self.add_rotate_component(state_x.id, state_x.input_bit_positions, WORD_SIZE, rx)
        rot_x = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state_y, rot_x])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_y = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # x <- x XOR c
        inputs_id, inputs_pos = get_inputs_parameter([state_x, ci])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state_x, state_y
