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


from claasp.graph.bit_builder import BitGraphPrimitive, BitState
from claasp.primitive_inputs import INPUT_KEY, INPUT_PLAINTEXT

SBOX = [
    [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2],
    [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],
    [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],
    [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],
    [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],
    [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],
    [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],
    [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1],
]

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64, "key_bit_size": 256, "number_of_rounds": 32},
]


class Gost(BitGraphPrimitive):
    """
    Construct an instance of the Gost class.

    This class is used to store compact representations of a primitive, used to generate the corresponding primitive.

    INPUT:
    - ``block_bit_size`` -- **integer** (default: `64`); primitive block bit size.
    - ``key_bit_size`` -- **integer** (default: `256`); primitive key bit size.
    - ``number_of_rounds`` -- **integer** (default: `32`); number of rounds of the primitive.

    EXAMPLES::

        >>> primitive = Gost()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x78b6bd4a81726659', 63)
    """

    def __init__(
        self,
        block_bit_size: int = 64,
        key_bit_size: int = 256,
        number_of_rounds: int = 32,
    ) -> None:
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.half_block_size = self.block_bit_size // 2
        self.n_key_ranges = self.key_bit_size // self.half_block_size

        super().__init__(
            family_name="gost",
            primitive_type="block_cipher",
            primitive_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            primitive_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            primitive_output_bit_size=self.block_bit_size,
        )

        plaintext = BitState(
            [INPUT_PLAINTEXT, INPUT_PLAINTEXT, INPUT_PLAINTEXT],
            [
                list(range(self.half_block_size)),
                list(range(self.half_block_size, self.block_bit_size)),
                list(range(self.half_block_size, self.block_bit_size)),
            ],
        )

        bit_positions = [
            list(range(self.half_block_size * i, self.half_block_size * (i + 1)))
            for i in range(self.n_key_ranges)
        ]

        key = BitState(
            [INPUT_KEY for _ in range(self.n_key_ranges)],
            bit_positions,
        )

        for r in range(number_of_rounds):
            self._builder.add_round()

            round_key = self.update_key(key, r)

            plaintext = self._add_round_key(plaintext, round_key)
            plaintext = self.sbox(plaintext)
            plaintext = self.rotate(plaintext)
            plaintext = self.xor(plaintext)

            if r == number_of_rounds - 1:
                continue

            plaintext = self.swap_blocks(plaintext)

            self.add_round_key_output_component(key.id, key.input_bit_positions, self.key_bit_size)
            self.add_round_output_component(
                plaintext.id, plaintext.input_bit_positions, self.block_bit_size
            )

        self.add_primitive_output_component(
            plaintext.id, plaintext.input_bit_positions, self.block_bit_size
        )

    def _add_round_key(self, plaintext: BitState, key: BitState) -> BitState:
        plaintext_id = self.add_modadd_component(
            [plaintext.id[-1], key.id],
            [plaintext.input_bit_positions[-1]] + key.input_bit_positions,
            self.half_block_size,
        ).id

        return BitState(
            [plaintext.id[0], plaintext.id[1], plaintext_id],
            [
                plaintext.input_bit_positions[0],
                plaintext.input_bit_positions[1],
                list(range(self.half_block_size)),
            ],
        )

    def sbox(self, plaintext: BitState) -> BitState:
        """Build the sbox stage in this primitive's typed operation graph."""
        plaintext_ids = []

        for i, sbox in enumerate(SBOX):
            plaintext_ids += [
                self.add_sbox_component(
                    [plaintext.id[-1]], [list(range(4 * i, 4 * (i + 1)))], 4, sbox
                ).id
            ]

        return BitState(
            [plaintext.id[0], plaintext.id[1]] + plaintext_ids,
            [plaintext.input_bit_positions[0], plaintext.input_bit_positions[1]]
            + [list(range(4)) for _ in range(len(SBOX))],
        )

    def rotate(self, plaintext: BitState) -> BitState:
        """Build the rotate stage in this primitive's typed operation graph."""
        plaintext_id = self.add_rotate_component(
            plaintext.id[2:],
            plaintext.input_bit_positions[2:],
            self.half_block_size,
            -11,
        ).id

        return BitState(
            [plaintext.id[0], plaintext.id[1], plaintext_id],
            [
                plaintext.input_bit_positions[0],
                plaintext.input_bit_positions[1],
                list(range(self.half_block_size)),
            ],
        )

    def xor(self, plaintext: BitState) -> BitState:
        """Build the xor stage in this primitive's typed operation graph."""
        plaintext_id = self.add_xor_component(
            [plaintext.id[0], plaintext.id[2]],
            [plaintext.input_bit_positions[0]] + [plaintext.input_bit_positions[2]],
            self.half_block_size,
        ).id

        return BitState(
            [plaintext_id, plaintext.id[1]],
            [list(range(self.half_block_size)), plaintext.input_bit_positions[1]],
        )

    def swap_blocks(self, plaintext: BitState) -> BitState:
        """Build the swap blocks stage in this primitive's typed operation graph."""
        return BitState(plaintext.id[::-1], plaintext.input_bit_positions[::-1])

    def update_key(self, key: BitState, r: int) -> BitState:
        """Build the update key transition in this primitive's typed operation graph."""
        if r <= 23:
            return BitState(key.id[r % 8], [key.input_bit_positions[r % 8]])

        return BitState(key.id[7 - (r % 8)], [key.input_bit_positions[7 - (r % 8)]])
