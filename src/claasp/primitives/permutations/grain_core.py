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

"""Grain v1 initialization-core permutation."""

from claasp.graph.bit_builder import BitGraphPrimitive, coerce_exact_int
from claasp.primitive_inputs import INPUT_STATE, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 160}]

# Absolute positions 0..79 denote LFSR bits s_i and 80..159 denote NFSR
# bits b_i. During initialization the Grain output bit z_i is fed back
# into both registers.
LFSR_CORE_POLY = [
    [0],
    [13],
    [23],
    [38],
    [51],
    [62],
    [25],
    [143],
    [3, 64],
    [46, 64],
    [64, 143],
    [3, 25, 46],
    [3, 46, 64],
    [3, 46, 143],
    [25, 46, 143],
    [46, 64, 143],
    [81],
    [82],
    [84],
    [90],
    [111],
    [123],
    [136],
]

NFSR_CORE_POLY = [
    [80],
    [89],
    [94],
    [101],
    [108],
    [113],
    [117],
    [125],
    [132],
    [140],
    [142],
    [0],
    [143, 140],
    [117, 113],
    [95, 89],
    [140, 132, 125],
    [113, 108, 101],
    [143, 125, 108, 89],
    [140, 132, 117, 113],
    [143, 140, 101, 95],
    [143, 140, 132, 125, 117],
    [113, 108, 101, 95, 89],
    [132, 125, 117, 113, 108, 101],
    [25],
    [143],
    [3, 64],
    [46, 64],
    [64, 143],
    [3, 25, 46],
    [3, 46, 64],
    [3, 46, 143],
    [25, 46, 143],
    [46, 64, 143],
    [81],
    [82],
    [84],
    [90],
    [111],
    [123],
    [136],
]

GRAIN_CORE_DESCRIPTION = [[[80, LFSR_CORE_POLY], [80, NFSR_CORE_POLY]], 1]


class GrainCore(BitGraphPrimitive):
    """Build the 160-clock initialization core of Grain v1 (Grain-80).

    The 160-bit input concatenates the 80-bit LFSR ``s`` and 80-bit NFSR
    ``b``. Positions 0 through 79 hold ``s_0`` through ``s_79``;
    positions 80 through 159 hold ``b_0`` through ``b_79``. Each round
    performs one initialization clock and feeds the output bit back into
    both registers. This primitive deliberately excludes key/IV loading
    and the later keystream-generation mode.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: ``None``); positive
      number of initialization clocks; ``None`` selects the Grain v1
      standard value of 160

    OUTPUT:

    - the updated 160-bit LFSR/NFSR state

    RAISES:

    - ``ValueError`` -- if ``number_of_rounds`` is not a positive integer

    EXAMPLES::

        >>> primitive = GrainCore()
        >>> initial_state = 0x0000000000000000FFFF00000000000000000000
        >>> hex(primitive.evaluate(initial_state))
        '0x4eb431bcc5344efb12da6d7b0599918a2f079726'
        >>> GrainCore(number_of_rounds=0)
        Traceback (most recent call last):
        ...
        ValueError: number_of_rounds must be a positive integer
    """

    def __init__(self, number_of_rounds=None):
        if number_of_rounds is None:
            rounds = PARAMETERS_CONFIGURATION_LIST[0]["number_of_rounds"]
        else:
            try:
                rounds = coerce_exact_int(number_of_rounds, "number_of_rounds")
            except ValueError:
                raise ValueError("number_of_rounds must be a positive integer") from None
            if rounds <= 0:
                raise ValueError("number_of_rounds must be a positive integer")

        self.state_bit_size = 160
        super().__init__(
            family_name="grain_core",
            primitive_type=PERMUTATION,
            primitive_inputs=[INPUT_STATE],
            primitive_inputs_bit_size=[self.state_bit_size],
            primitive_output_bit_size=self.state_bit_size,
        )

        state_id = INPUT_STATE
        state_positions = list(range(self.state_bit_size))
        for _ in range(rounds):
            self._builder.add_round()
            state_id = self.add_fsr_component(
                [state_id],
                [state_positions],
                self.state_bit_size,
                GRAIN_CORE_DESCRIPTION,
            ).id
            state_positions = list(range(self.state_bit_size))
            self.add_round_output_component([state_id], [state_positions], self.state_bit_size)

        self.add_primitive_output_component([state_id], [state_positions], self.state_bit_size)
