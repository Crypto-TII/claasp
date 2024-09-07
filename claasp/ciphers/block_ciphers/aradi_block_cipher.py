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
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY

input_types = [INPUT_KEY, INPUT_PLAINTEXT]
PARAMETERS_CONFIGURATION_LIST = [{'block_bit_size': 128, 'key_bit_size': 256, 'number_of_rounds': 16}]


def get_key_word_bit_indexes(word_index):
    return list(range(32 * (8 - word_index - 1), 32 * (8 - word_index)))


class AradiBlockCipher(Cipher):
    """
    Construct an instance of the AradiBlockCipher class.

    This class is used to store compact representations of a cipher,
    used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); the bit size of the cipher's input and output blocks.
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``sub_keys_zero`` -- **boolean** (default: `False`)
    - ``transformations_flag`` -- **boolean** (default: `True`)

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.aradi_block_cipher import AradiBlockCipher
        sage: aradi = AradiBlockCipher(number_of_rounds=16)
        sage: aradi.evaluate([0, 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100])
        83791582030165712186104466959690447122
    """

    def __init__(self, number_of_rounds=16):
        self.block_bit_size = 128
        self.key_bit_size = 256
        self.WORD_SIZE = 32

        super().__init__(family_name="aradi",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)
        self.A = [11, 10, 9, 8]
        self.B = [8, 9, 4, 9]
        self.C = [14, 11, 14, 7]
        state = INPUT_PLAINTEXT
        key = INPUT_KEY

        for round_i in range(number_of_rounds):
            self.add_round()
            round_key = self.get_round_key_id(key, round_i)
            state = self.round_function(state, round_key, round_i)
            key = self.update_key(key, round_i)

        round_key = self.get_round_key_id(key, 0)
        w = self.add_XOR_component(
            [round_key, state], [list(range(32)), list(range(32))], 32
        ).id
        x = self.add_XOR_component(
            [round_key, state], [list(range(32, 64)), list(range(32, 64))], 32
        ).id
        y = self.add_XOR_component(
            [round_key, state], [list(range(64, 96)), list(range(64, 96))], 32
        ).id
        z = self.add_XOR_component(
            [round_key, state],
            [list(range(96, 128)),
             list(range(96, 128))],
            32
        ).id
        self.add_cipher_output_component(
            [w, x, y, z], [list(range(32)) for _ in range(4)], 128
        )

    def get_round_key_id(self, key, round_i):
        j = round_i % 2
        return self.add_round_key_output_component(
            [key, key, key, key],
            [get_key_word_bit_indexes(4 * j + i) for i in range(4)],
            128
        ).id

    def l_function(self, xy_id_links, x_bits, y_bits, round_index):
        j = round_index % 4
        rot_x_a = self.add_rotate_component(
            [xy_id_links], [x_bits], 16, -self.A[j]
        ).id
        rot_x_b = self.add_rotate_component(
            [xy_id_links], [x_bits], 16, -self.B[j]
        ).id
        rot_y_a = self.add_rotate_component(
            [xy_id_links], [y_bits], 16, -self.A[j]
        ).id
        rot_y_c = self.add_rotate_component(
            [xy_id_links], [y_bits], 16, -self.C[j]
        ).id

        left_part = self.add_XOR_component([xy_id_links] + [rot_x_a, rot_y_c],
                                           [x_bits] + [list(range(16)), list(range(16))], 16).id
        right_part = self.add_XOR_component([xy_id_links] + [rot_y_a, rot_x_b],
                                            [y_bits] + [list(range(16)), list(range(16))], 16).id
        return left_part, right_part

    def m_function(self, i, j, xy_id_links, xy_input_bits):
        y_indices = xy_input_bits[32:64]
        x_indices = xy_input_bits[:32]
        rot_i_y = self.add_rotate_component(xy_id_links, [y_indices], 32, -i).id
        rot_j_x = self.add_rotate_component(xy_id_links, [x_indices], 32, -j).id
        left_part = self.add_XOR_component(xy_id_links + [rot_i_y, rot_j_x],
                                           [x_indices] + [list(range(32)) for _ in range(2)], 32).id
        right_part = self.add_XOR_component(
            xy_id_links + [rot_i_y], [x_indices] + [list(range(32))], 32
        ).id
        return left_part, right_part

    def update_key(self, key, round_i):
        round_constant = self.add_constant_component(32, round_i).id
        k1, k0 = self.m_function(
            1, 3, [key], get_key_word_bit_indexes(1) + get_key_word_bit_indexes(0)
        )
        k3, k2 = self.m_function(
            9, 28, [key], get_key_word_bit_indexes(3) + get_key_word_bit_indexes(2)
        )
        k5, k4 = self.m_function(
            1, 3, [key], get_key_word_bit_indexes(5) + get_key_word_bit_indexes(4)
        )
        k7, k6 = self.m_function(
            9, 28, [key], get_key_word_bit_indexes(7) + get_key_word_bit_indexes(6)
        )
        k7 = self.add_XOR_component(
            [k7, round_constant], [list(range(32)) for _ in range(2)], 32
        ).id
        if round_i % 2 == 0:
            updated_key = self.add_intermediate_output_component([k7, k5, k6, k4, k3, k1, k2, k0],
                                                                 [list(range(32)) for _ in range(8)], 256,
                                                                 f"key_{round_i}")
        else:
            updated_key = self.add_intermediate_output_component([k7, k3, k5, k1, k6, k2, k4, k0],
                                                                 [list(range(32)) for _ in range(8)], 256,
                                                                 f"key_{round_i}")
        return updated_key.id

    def round_function(self, state, round_key, round_i):
        w_ind = list(range(32))
        x_ind = list(range(32, 64))
        y_ind = list(range(64, 96))
        z_ind = list(range(96, 128))
        w = self.add_XOR_component([round_key, state], [w_ind, w_ind], 32).id
        x = self.add_XOR_component([round_key, state], [x_ind, x_ind], 32).id
        y = self.add_XOR_component([round_key, state], [y_ind, y_ind], 32).id
        z = self.add_XOR_component([round_key, state], [z_ind, z_ind], 32).id
        # SBOX
        wy = self.add_AND_component([w, y], [list(range(32)) for _ in range(2)], 32).id
        x = self.add_XOR_component([x, wy], [list(range(32)) for _ in range(2)], 32).id

        xy = self.add_AND_component([x, y], [list(range(32)) for _ in range(2)], 32).id
        z = self.add_XOR_component([z, xy], [list(range(32)) for _ in range(2)], 32).id

        wz = self.add_AND_component([w, z], [list(range(32)) for _ in range(2)], 32).id
        y = self.add_XOR_component([y, wz], [list(range(32)) for _ in range(2)], 32).id

        xz = self.add_AND_component([x, z], [list(range(32)) for _ in range(2)], 32).id
        w = self.add_XOR_component([w, xz], [list(range(32)) for _ in range(2)], 32).id

        # L Function
        # w_id_links = [sb_id for sb_id in sb_outputs]
        # w_input_bits = [[0] for _ in sb_outputs]
        x_bits = list(range(16))
        y_bits = list(range(16, 32))
        wl, wr = self.l_function(
            w, x_bits, y_bits, round_i
        )

        xl, xr = self.l_function(
            x, x_bits, y_bits, round_i
        )

        yl, yr = self.l_function(
            y, x_bits, y_bits, round_i
        )

        zl, zr = self.l_function(
            z, x_bits, y_bits, round_i
        )

        # Round output
        state = self.add_round_output_component(
            [wl, wr, xl, xr, yl, yr, zl, zr],
            [list(range(16)) for _ in range(8)],
            128
        )
        return state.id
