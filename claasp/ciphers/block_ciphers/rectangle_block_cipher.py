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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT
from claasp.utils.utils import extract_inputs

PARAMETERS_CONFIGURATION_LIST = [
    {"key_bit_size": 80, "number_of_rounds": 25},
    {"key_bit_size": 128, "number_of_rounds": 25},
]

SBOX = [0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9, 0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2]
ROTATIONS = [0, 1, 12, 13]
# fmt: off
RC = [
    0x01, 0x02, 0x04, 0x09, 0x12, 0x05, 0x0B, 0x16, 0x0C, 0x19, 0x13, 0x07, 0x0F,
    0x1F, 0x1E, 0x1C, 0x18, 0x11, 0x03, 0x06, 0x0D, 0x1B, 0x17, 0x0E, 0x1D,
]
# fmt: on


class RectangleBlockCipher(Cipher):
    """
    Construct an instance of the RectangleBlockCipher class.
    Reference: https://eprint.iacr.org/2014/084

    The 64-bit state is a 4 x 16 array of bits, row i being bits 16i+15,...,16i of the state, with row 0 the
    least significant one. The S-box acts on the 16 columns and ShiftRow rotates row i to the left by 0, 1, 12
    and 13 bits. The key register is a 5 x 16 (80-bit key) or a 4 x 32 (128-bit key) array of bits.

    INPUT:

    - ``key_bit_size`` -- **integer** (default: `80`); cipher key bit size of the cipher, 80 or 128
    - ``number_of_rounds`` -- **integer** (default: `25`); number of rounds of the cipher, from 1 to 25

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.rectangle_block_cipher import RectangleBlockCipher
        sage: rectangle = RectangleBlockCipher()
        sage: rectangle.number_of_rounds
        25

        sage: rectangle.component_from(0, 0).id
        'xor_0_0'

        sage: RectangleBlockCipher(number_of_rounds=2).number_of_rounds
        2

        sage: rectangle.evaluate([0x0000000000000000, 0x00000000000000000000]) == 0x0874E8B1E3542D96
        True
    """

    def __init__(self, key_bit_size=80, number_of_rounds=25):
        if key_bit_size not in (80, 128):
            raise ValueError("Key size must either be 80 or 128 bits.")
        if not 1 <= number_of_rounds <= len(RC):
            raise ValueError("Number of rounds must be between 1 and 25.")

        self.block_bit_size = 64
        self.key_bit_size = key_bit_size
        self.key_row_bit_size = 16 if key_bit_size == 80 else 32
        self.number_of_key_rows = key_bit_size // self.key_row_bit_size
        self.number_of_key_sboxes = self.key_row_bit_size // 4
        n = number_of_rounds

        super().__init__(
            family_name="rectangle",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        data = [INPUT_PLAINTEXT], [list(range(self.block_bit_size))]
        key = [INPUT_KEY], [list(range(self.key_bit_size))]

        for r in range(n):
            self.add_round()

            data = self.add_round_key(data, key)
            sbox_outputs = self.sub_column(data)
            data = self.shift_row(sbox_outputs)

            key = self.update_key_register(key, r)

            if r == n - 1:
                data = self.add_round_key(data, key)

            self.add_round_key_output_component(key[0], key[1], self.key_bit_size)
            self.add_round_output_component(data[0], data[1], self.block_bit_size)

        self.add_cipher_output_component(data[0], data[1], self.block_bit_size)

    def key_row_positions(self, i, number_of_bits=None): 
        number_of_bits = self.key_row_bit_size if number_of_bits is None else number_of_bits
        end = (self.number_of_key_rows - i) * self.key_row_bit_size
        return list(range(end - number_of_bits, end))

    def add_round_key(self, data, key):
        round_key_positions = [p for i in reversed(range(4)) for p in self.key_row_positions(i, 16)]
        key_id_list, key_bit_positions = extract_inputs(*key, round_key_positions)
        new_data_id = self.add_xor_component(data[0] + key_id_list, data[1] + key_bit_positions, self.block_bit_size).id

        return [new_data_id], [list(range(self.block_bit_size))]

    def sub_column(self, data):
        sbox_outputs = [""] * 16

        for j in range(16):
            sbox_outputs[j] = self.add_sbox_component(data[0], [[15 - j, 31 - j, 47 - j, 63 - j]], 4, SBOX).id

        return sbox_outputs

    def shift_row(self, sbox_outputs):
        row_ids = [sbox_outputs[j] for j in reversed(range(16))]
        data_ids = []
        data_bit_positions = []

        for i in reversed(range(4)):
            row_bit_positions = [[3 - i]] * 16
            if ROTATIONS[i] == 0:
                data_ids += row_ids
                data_bit_positions += row_bit_positions
            else:
                rot = self.add_rotate_component(row_ids, row_bit_positions, 16, -ROTATIONS[i]).id
                data_ids.append(rot)
                data_bit_positions.append(list(range(16)))

        return data_ids, data_bit_positions

    def update_key_register(self, key, r):
        w = self.key_row_bit_size
        m = self.number_of_key_sboxes

        sbox_outputs = [""] * m
        for j in range(m):
            column = [self.key_row_positions(i)[w - 1 - j] for i in reversed(range(4))]
            sbox_id_list, sbox_bit_positions = extract_inputs(*key, column)
            sbox_outputs[j] = self.add_sbox_component(sbox_id_list, sbox_bit_positions, 4, SBOX).id

        rows = []
        for i in range(self.number_of_key_rows):
            if i < 4:
                row_ids, row_bit_positions = extract_inputs(*key, self.key_row_positions(i)[: w - m])
                row_ids += [sbox_outputs[j] for j in reversed(range(m))]
                row_bit_positions += [[3 - i]] * m
            else:
                row_ids, row_bit_positions = extract_inputs(*key, self.key_row_positions(i))
            rows.append((row_ids, row_bit_positions))

        rot_0 = self.add_rotate_component(rows[0][0], rows[0][1], w, -8).id
        row_0 = self.add_xor_component([rot_0] + rows[1][0], [list(range(w))] + rows[1][1], w).id
        constant_id = self.add_constant_component(5, RC[r]).id
        row_0_rc = self.add_xor_component([row_0, constant_id], [list(range(w - 5, w)), list(range(5))], 5).id
        new_row_0 = [row_0, row_0_rc], [list(range(w - 5)), list(range(5))]

        if self.key_bit_size == 80:
            rot_3 = self.add_rotate_component(rows[3][0], rows[3][1], w, -12).id
            row_3 = self.add_xor_component([rot_3] + rows[4][0], [list(range(w))] + rows[4][1], w).id
            new_rows = [rows[0], ([row_3], [list(range(w))]), rows[3], rows[2], new_row_0]
        else:
            rot_2 = self.add_rotate_component(rows[2][0], rows[2][1], w, -16).id
            row_2 = self.add_xor_component([rot_2] + rows[3][0], [list(range(w))] + rows[3][1], w).id
            new_rows = [rows[0], ([row_2], [list(range(w))]), rows[2], new_row_0]

        key_ids = [i for row in new_rows for i in row[0]]
        key_bit_positions = [p for row in new_rows for p in row[1]]

        return key_ids, key_bit_positions
