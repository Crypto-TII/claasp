"""Canonical PRINCE block primitive."""

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

from claasp.graph.bit_builder import BitGraphPrimitive
from claasp.primitive_inputs import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

round_constants = [
    0x0000000000000000,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0x7EF84F78FD955CB1,
    0x85840851F1AC43AA,
    0xC882D32F25323C54,
    0x64A51195E0E3610D,
    0xD3B5A399CA0C2399,
    0xC0AC29B7C97C50DD,
]


m0 = [[0, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]]
m1 = [[1, 0, 0, 0], [0, 0, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]]
m2 = [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 0], [0, 0, 0, 1]]
m3 = [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 0]]


def _block_matrix(block_rows):
    return [
        [value for block in block_row for value in block[row]]
        for block_row in block_rows
        for row in range(len(block_row[0]))
    ]


def get_shift_rows_matrix():
    temp_matrix = [[0 for _ in range(64)] for _ in range(64)]
    idx = 0
    for nibble_idx in range(16):
        for i in range(4):
            original_position = nibble_idx * 4 + i
            new_position = idx * 4 + i
            temp_matrix[new_position][original_position] = 1
        idx = (idx + 5) % 16

    return temp_matrix


def get_shift_rows_matrix_inverse():
    temp_matrix = [[0 for _ in range(64)] for _ in range(64)]

    idx = 0
    for nibble_idx in range(16):
        for i in range(4):
            original_position = nibble_idx * 4 + i
            new_position = idx * 4 + i
            temp_matrix[new_position][original_position] = 1
        idx = (idx + 13) % 16

    return temp_matrix


def get_m_prime():
    m_hat_0 = _block_matrix(
        [[m0, m1, m2, m3], [m1, m2, m3, m0], [m2, m3, m0, m1], [m3, m0, m1, m2]]
    )

    m_hat_1 = _block_matrix(
        [[m1, m2, m3, m0], [m2, m3, m0, m1], [m3, m0, m1, m2], [m0, m1, m2, m3]]
    )

    zero = [[0] * 16 for _ in range(16)]
    return _block_matrix(
        [
            [m_hat_0, zero, zero, zero],
            [zero, m_hat_1, zero, zero],
            [zero, zero, m_hat_1, zero],
            [zero, zero, zero, m_hat_0],
        ]
    )


sbox = [0xB, 0xF, 0x3, 0x2, 0xA, 0xC, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xE, 0x5, 0xD, 0x4]
inverse_sbox = [0xB, 0x7, 0x3, 0x2, 0xF, 0xD, 0x8, 0x9, 0xA, 0x6, 0x4, 0x0, 0x5, 0xE, 0xC, 0x1]


class Prince(BitGraphPrimitive):
    """
    Return a primitive object of Prince Block Primitive.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the primitive. Must be greater or equal than 1.

    EXAMPLES::

        >>> from claasp.primitives.block_ciphers.prince import Prince
        >>> prince = Prince()
        >>> key = 0xffffffffffffffff0000000000000000
        >>> plaintext = 0x0000000000000000
        >>> ciphertext = 0x9fb51935fc3df524
        >>> prince.evaluate(plaintext, key) == ciphertext
        True
    """

    def generate_first_rounds(self, current_state, number_of_rounds):
        """Build the generate first rounds stage in this primitive's typed operation graph."""
        for round_idx in range(1, number_of_rounds // 2):
            sbox_layer = []

            for i in range(16):
                sbox_layer.append(
                    self.add_sbox_component(
                        [current_state], [[i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]], 4, sbox
                    )
                )

            input_ids = [c.id for c in sbox_layer]
            input_bit_positions = [list(range(4)) for i in range(16)]
            after_m_matrix = self.add_linear_layer_component(
                input_ids, input_bit_positions, 64, get_m_prime()
            )
            after_shift_row = self.add_linear_layer_component(
                [after_m_matrix.id], [list(range(64))], 64, get_shift_rows_matrix()
            )
            current_state = after_shift_row.id
            round_constant = self.add_constant_component(64, round_constants[round_idx])
            current_state = self.add_xor_component(
                [current_state, round_constant.id], [list(range(64)), list(range(64))], 64
            ).id

            round_key_xor = self.add_xor_component(
                [current_state, INPUT_KEY], [list(range(64)), list(range(64, 128))], 64
            )
            current_state = round_key_xor.id
            self.add_round_output_component([current_state], [[i for i in range(64)]], 64)
            self._builder.add_round()
        return current_state

    def prince_core(self, xor_initial, number_of_rounds):
        """Build the prince core stage in this primitive's typed operation graph."""
        round_constant_0 = self.add_constant_component(64, round_constants[0])
        round_constant_xor_key_1 = self.add_xor_component(
            [round_constant_0.id, INPUT_KEY], [list(range(64)), list(range(64, 128))], 64
        ).id

        current_state = self.add_xor_component(
            [xor_initial, round_constant_xor_key_1], [list(range(64)), list(range(64))], 64
        )

        current_state = current_state.id
        current_state = self.generate_first_rounds(current_state, number_of_rounds)

        sboxes = []
        for i in range(16):
            sboxes.append(
                self.add_sbox_component(
                    [current_state], [[i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]], 4, sbox
                )
            )
        input_ids = [sbox_layer.id for sbox_layer in sboxes]
        input_bit_positions = [list(range(4)) for i in range(16)]
        current_state = self.add_linear_layer_component(
            input_ids, input_bit_positions, 64, get_m_prime()
        )

        sboxes = []
        for i in range(16):
            sboxes.append(
                self.add_sbox_component(
                    [current_state.id], [[i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]], 4, inverse_sbox
                )
            )

        input_ids = [sbox_layer.id for sbox_layer in sboxes]
        input_bit_positions = [list(range(4)) for i in range(16)]

        input_ids, input_bit_positions = self.get_last_rounds(
            number_of_rounds, input_ids, input_bit_positions
        )

        round_constant_11 = self.add_constant_component(64, round_constants[11])

        constant_xor_key1 = self.add_xor_component(
            [round_constant_11.id, INPUT_KEY], [list(range(64)), list(range(64, 128))], 64
        )

        final_xor = self.add_xor_component(
            input_ids + [constant_xor_key1.id], input_bit_positions + [list(range(64))], 64
        )

        return final_xor

    def pre_whitening(self):
        """Build the pre whitening stage in this primitive's typed operation graph."""
        self._builder.add_round()
        return self.add_xor_component(
            [INPUT_PLAINTEXT, INPUT_KEY], [list(range(64)), list(range(64))], 64
        ).id

    def get_k0_prime(self, key_component_id):
        """Return the k0 prime used while authoring this primitive graph."""
        k0_rot = self.add_rotate_component([key_component_id], [list(range(64))], 64, 1).id
        k0_shift = self.add_shift_component([key_component_id], [list(range(64))], 64, 63).id

        k0_prime = self.add_xor_component(
            [k0_rot, k0_shift], [list(range(64)), list(range(64))], 64
        ).id

        return k0_prime

    def pos_whitening(self, final_xor):
        """Build the pos whitening stage in this primitive's typed operation graph."""
        k0_prime = self.get_k0_prime(INPUT_KEY)
        return self.add_xor_component(
            [final_xor.id, k0_prime], [list(range(64)), list(range(64))], 64
        )

    def get_last_rounds(self, number_of_rounds, input_ids, input_bit_positions):
        """Return the last rounds used while authoring this primitive graph."""
        for round_idx in range(
            number_of_rounds // 2, (number_of_rounds // 2 - 1) + number_of_rounds // 2
        ):
            self._builder.add_round()
            round_constant_0 = self.add_constant_component(64, round_constants[round_idx])
            constant_xor_key1 = self.add_xor_component(
                [round_constant_0.id, INPUT_KEY], [list(range(64)), list(range(64, 128))], 64
            )
            current_state = self.add_xor_component(
                input_ids + [constant_xor_key1.id], input_bit_positions + [list(range(64))], 64
            )

            after_shift_row = self.add_linear_layer_component(
                [current_state.id], [list(range(64))], 64, get_shift_rows_matrix_inverse()
            )

            current_state = self.add_linear_layer_component(
                [after_shift_row.id], [list(range(64))], 64, get_m_prime()
            )

            sbox_layer = []
            for i in range(16):
                sbox_layer.append(
                    self.add_sbox_component(
                        [current_state.id],
                        [[i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]],
                        4,
                        inverse_sbox,
                    )
                )

            input_ids = [c.id for c in sbox_layer]
            input_bit_positions = [list(range(4)) for i in range(16)]
            self.add_round_output_component(
                input_ids,
                [list(range(4)) for _ in range(16)],
                64,
            )
        return input_ids, input_bit_positions

    def __init__(self, number_of_rounds=12):
        super().__init__(
            family_name="prince",
            primitive_type=BLOCK_CIPHER,
            primitive_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            primitive_inputs_bit_size=[64, 128],
            primitive_output_bit_size=64,
        )
        pre_whitening = self.pre_whitening()
        final_xor = self.prince_core(pre_whitening, number_of_rounds)
        pos_whitening = self.pos_whitening(final_xor)
        self.add_primitive_output_component([pos_whitening.id], [list(range(64))], 64)
