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
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION
from claasp.utils.utils import get_inputs_parameter

WORD_SIZE = 32

# Rotation pairs (ry, rx) for the four Alzette sub-rounds.
# Sub-round i performs: x += ROT(y, ry), y ^= ROT(x, rx), x ^= c.
# Source: Algorithm 1 and Appendix C/D of [BBBGPUV2020]_.
ALZETTE_ROTATIONS = [(31, 24), (17, 17), (0, 31), (24, 16)]

# Round constants used in the SPARKLE permutation family (and recommended
# by the Alzette designers for instantiations).  Indexed c0 .. c7.
SPARKLE_CONSTANTS = [
    0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
    0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D,
]

PARAMETERS_CONFIGURATION_LIST = [{"round_constant": SPARKLE_CONSTANTS[0]}]


class AlzettePermutation(Cipher):
    """
    Construct an instance of the AlzettePermutation class.

    Alzette is a 64-bit ARX-box (permutation) that operates on two 32-bit
    words ``(x, y)`` with a 32-bit round constant ``c``.  It consists of
    four sub-rounds, each performing:

    1. ``x <- x + (y >>> ry)``  (modular addition with a rotation of y)
    2. ``y <- y XOR (x >>> rx)``  (XOR with a rotation of x)
    3. ``x <- x XOR c``          (XOR with the round constant)

    The rotation amounts ``(ry, rx)`` differ per sub-round:
    ``(31, 24)``, ``(17, 17)``, ``(0, 31)``, ``(24, 16)``.

    The 64-bit input is interpreted as ``x || y`` (``x`` occupying the
    most-significant 32 bits, ``y`` the least-significant 32 bits).

    INPUT:

    - ``round_constant`` -- **integer** (default: `0xB7E15162`); the 32-bit
      round constant ``c`` baked into the permutation.  The eight constants
      recommended by the designers for use in the SPARKLE permutation family
      are available as ``SPARKLE_CONSTANTS[0..7]`` in this module.

    EXAMPLES::

        sage: from claasp.ciphers.permutations.alzette_permutation import AlzettePermutation
        sage: alzette = AlzettePermutation()
        sage: alzette.number_of_rounds
        4

        sage: alzette.component_from(0, 0).id
        'constant_0_0'

        sage: alzette.evaluate([0x0000000000000000]) == 0x44dd4de9e5581f2d
        True
    """

    def __init__(self, round_constant=SPARKLE_CONSTANTS[0]):
        self.word_size = WORD_SIZE
        self.state_bit_size = 2 * WORD_SIZE

        super().__init__(
            family_name='alzette',
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        # Bake the round constant into a constant component that is reused
        # across all sub-rounds.  It is created inside the first round so
        # that number_of_rounds equals the number of Alzette sub-rounds (4).
        self.add_round()
        self.add_constant_component(WORD_SIZE, round_constant)
        ci = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # Initial state: x occupies bits 0..31, y occupies bits 32..63.
        state_x = ComponentState([INPUT_PLAINTEXT], [list(range(WORD_SIZE))])
        state_y = ComponentState([INPUT_PLAINTEXT], [list(range(WORD_SIZE, 2 * WORD_SIZE))])

        for sub_round_idx, (ry, rx) in enumerate(ALZETTE_ROTATIONS):
            state_x, state_y = self._alzette_sub_round(state_x, state_y, ci, ry, rx)

            inputs_id, inputs_pos = get_inputs_parameter([state_x, state_y])
            if sub_round_idx == len(ALZETTE_ROTATIONS) - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)
                self.add_round()

    def _alzette_sub_round(self, state_x, state_y, ci, ry, rx):
        """Perform one Alzette sub-round: x+=ROT(y,ry), y^=ROT(x,rx), x^=c."""
        # x <- x + ROT(y, ry)
        if ry == 0:
            # ROT(y, 0) is the identity — skip the rotate component.
            inputs_id, inputs_pos = get_inputs_parameter([state_x, state_y])
        else:
            self.add_rotate_component(
                state_y.id, state_y.input_bit_positions, WORD_SIZE, ry
            )
            rot_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            inputs_id, inputs_pos = get_inputs_parameter([state_x, rot_y])
        self.add_modadd_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # y <- y XOR ROT(x, rx)
        self.add_rotate_component(
            state_x.id, state_x.input_bit_positions, WORD_SIZE, rx
        )
        rot_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state_y, rot_x])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_y = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        # x <- x XOR c
        inputs_id, inputs_pos = get_inputs_parameter([state_x, ci])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state_x = ComponentState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state_x, state_y
