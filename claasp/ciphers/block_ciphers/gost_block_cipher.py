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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY


SBOX = [
    [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1],
    [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],
    [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],
    [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],
    [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],
    [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],
    [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],
    [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2],
]

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64, "key_bit_size": 256, "number_of_rounds": 32},
]


class GostBlockCipher(Cipher):
    """
    Construct an instance of the GostBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:
    - ``block_bit_size`` -- **integer** (default: `64`); cipher block bit size.
    - ``key_bit_size`` -- **integer** (default: `256`); cipher key bit size.
    - ``number_of_rounds`` -- **integer** (default: `32`); number of rounds of the cipher.

    EXAMPLES::
        sage: from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher
        sage: gost = GostBlockCipher()
        sage: gost.number_of_rounds
        32
        sage: gost.component_from(0, 0).id
        modadd_0_0
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
            cipher_type="block_cipher",
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        plaintext = ComponentState(
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

        key = ComponentState(
            [INPUT_KEY for _ in range(self.n_key_ranges)],
            bit_positions,
        )

        for r in range(number_of_rounds):
            self.add_round()

            round_key = self.update_key(key, r)

            plaintext = self.add_round_key(plaintext, round_key)
            plaintext = self.sbox(plaintext)
            plaintext = self.rotate(plaintext)
            plaintext = self.xor(plaintext)

            if r == number_of_rounds - 1:
                continue

            plaintext = self.swap_blocks(plaintext)

            self.add_round_key_output_component(
                key.id, key.input_bit_positions, self.key_bit_size
            )
            self.add_round_output_component(
                plaintext.id, plaintext.input_bit_positions, self.block_bit_size
            )

        self.add_cipher_output_component(
            plaintext.id, plaintext.input_bit_positions, self.block_bit_size
        )

    def add_round_key(
        self, plaintext: ComponentState, key: ComponentState
    ) -> ComponentState:
        plaintext_id = self.add_MODADD_component(
            plaintext.id[-1] + key.id,
            plaintext.input_bit_positions[-1] + key.input_bit_positions,
            self.half_block_size,
        ).id

        return ComponentState(
            [plaintext.id[0], plaintext.id[1], plaintext_id],
            [
                plaintext.input_bit_positions[0],
                plaintext.input_bit_positions[1],
                list(range(self.half_block_size)),
            ],
        )

    def sbox(self, plaintext: ComponentState) -> ComponentState:
        plaintext_ids = []

        for i, sbox in enumerate(SBOX):
            plaintext_ids += [
                self.add_SBOX_component(
                    plaintext.id[-1], list(range(4 * i, 4 * (i + 1))), 4, sbox
                ).id
            ]

        return ComponentState(
            [plaintext.id[0], plaintext.id[1]] + plaintext_ids,
            [plaintext.input_bit_positions[0], plaintext.input_bit_positions[1]]
            + [list(range(4)) for _ in range(len(SBOX))],
        )

    def rotate(self, plaintext: ComponentState) -> ComponentState:
        plaintext_id = self.add_rotate_component(
            plaintext.id[2:],
            plaintext.input_bit_positions[2:],
            self.half_block_size,
            -11,
        ).id

        return ComponentState(
            [plaintext.id[0], plaintext.id[1], plaintext_id],
            [
                plaintext.input_bit_positions[0],
                plaintext.input_bit_positions[1],
                list(range(self.half_block_size)),
            ],
        )

    def xor(self, plaintext: ComponentState) -> ComponentState:
        plaintext_id = self.add_XOR_component(
            plaintext.id[0] + plaintext.id[2],
            plaintext.input_bit_positions[0] + plaintext.input_bit_positions[2],
            self.half_block_size,
        ).id

        return ComponentState(
            [plaintext_id, plaintext.id[1]],
            [list(range(self.half_block_size)), plaintext.input_bit_positions[1]],
        )

    def swap_blocks(self, plaintext: ComponentState) -> ComponentState:
        return ComponentState(plaintext.id[::-1], plaintext.input_bit_positions[::-1])

    def update_key(self, key: ComponentState, r: int) -> ComponentState:
        if r <= 23:
            return ComponentState(key.id[r % 8], key.input_bit_positions[r % 8])

        return ComponentState(key.id[7 - (r % 8)], key.input_bit_positions[7 - (r % 8)])
