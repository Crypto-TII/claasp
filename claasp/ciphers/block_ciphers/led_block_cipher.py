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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

M = [[0x4, 0x1, 0x2, 0x2], [0x8, 0x6, 0x5, 0x6], [0xB, 0xE, 0xA, 0x9], [0x2, 0x2, 0xF, 0xB]]

IRREDUCIBLE_POLYNOMIAL = 0x13

PARAMETERS_CONFIGURATION_LIST = [
    {"key_bit_size": 64, "number_of_rounds": 32, "number_of_steps": 8},
]


class LedBlockCipher(Cipher):
    def __init__(self, key_bit_size=64, number_of_rounds=32, number_of_steps=8):
        self.block_bit_size = 64
        self.key_bit_size = key_bit_size
        self.number_of_steps = number_of_steps
        self.cipher_type = BLOCK_CIPHER

        super().__init__(
            family_name="led",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        state = ComponentState([INPUT_PLAINTEXT], [list(range(self.block_bit_size))])
        key = ComponentState([INPUT_KEY], [list(range(self.key_bit_size))])

        round_number = 0

        self.add_round()
        state = self.add_round_key(state, key)
        for number_of_step in range(self.number_of_steps):
            for _ in range(4):
                state = self.add_constants(state, round_number)
                state = self.sub_cells(state)
                state = self.shift_rows(state)
                state = self.mix_columns(state)
                round_number += 1
            state = self.add_round_key(state, key)

            if number_of_step != self.number_of_steps - 1:
                self.add_round_output_component(state.id, state.input_bit_positions, self.block_bit_size)
                self.add_round()
            else:
                self.add_cipher_output_component(state.id, state.input_bit_positions, self.block_bit_size)

    def get_round_register(self, round_number):
        rc = [0, 0, 0, 0, 0, 0]
        for _ in range(round_number + 1):
            new_rc0 = rc[0] ^ rc[1] ^ 1
            rc = rc[1:] + [new_rc0]
        return rc

    def get_round_constant(self, round_number):
        register = self.get_round_register(round_number)
        rc_high = "".join(map(str, register[0:3]))
        rc_low = "".join(map(str, register[3:6]))
        rc_high_number = int(rc_high, 2)
        rc_low_number = int(rc_low, 2)

        ks_high = 4 if self.key_bit_size == 64 else 8

        constant = (
            ks_high << 60
            | rc_high_number << 56
            | (ks_high ^ 1) << 44
            | rc_low_number << 40
            | 2 << 28
            | rc_high_number << 24
            | 3 << 12
            | rc_low_number << 8
        )

        return constant

    def add_constants(self, state, round_number):
        constant = self.get_round_constant(round_number)
        const_id = self.add_constant_component(self.block_bit_size, constant).id

        xor_id = self.add_XOR_component(
            [*state.id, const_id],
            [*state.input_bit_positions, list(range(self.block_bit_size))],
            self.block_bit_size,
        ).id
        return ComponentState([xor_id], [list(range(self.block_bit_size))])

    def sub_cells(self, state):
        sbox_out_ids = []
        for i in range(16):
            id_sbox = self.add_SBOX_component(state.id, [state.input_bit_positions[0][i * 4 : (i + 1) * 4]], 4, sbox).id
            sbox_out_ids.append(id_sbox)
        return ComponentState(sbox_out_ids, [list(range(4))] * 16)

    def shift_rows(self, state):
        shifts = [0, 1, 2, 3]
        shifted = []

        for row in range(4):
            row_data = state.id[row * 4 : (row + 1) * 4]
            row_data = row_data[shifts[row] :] + row_data[: shifts[row]]
            shifted.extend(row_data)

        return ComponentState(shifted, [list(range(4))] * 16)

    def mix_columns(self, state):
        mix_columns_ids = []

        for col in range(4):
            col_ids = [state.id[row * 4 + col] for row in range(4)]
            col_pos = [state.input_bit_positions[row * 4 + col] for row in range(4)]

            mix_columns_id = self.add_mix_column_component(
                col_ids, col_pos, self.block_bit_size // 4, [M, IRREDUCIBLE_POLYNOMIAL, 4]
            ).id

            mix_columns_ids.append(mix_columns_id)

        new_state = []
        new_positions = []

        for i in range(4):
            new_state.extend(mix_columns_ids)
            new_positions.extend(list(range(4 * i, 4 * (i + 1))) for _ in range(4))

        return ComponentState(new_state, new_positions)

    def add_round_key(self, state, key):
        xor_id = self.add_XOR_component(
            [*state.id, *key.id], [*state.input_bit_positions, *key.input_bit_positions], self.block_bit_size
        ).id

        return ComponentState([xor_id], [list(range(self.block_bit_size))])
