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
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK
from claasp.utils.utils import extract_inputs
import numpy as np

MANTIS_ROUND_CONSTANTS = [
    0x13198a2e03707344,
    0xa4093822299f31d0,
    0x082efa98ec4e6c89,
    0x452821e638d01377,
    0xbe5466cf34e90c6c,
    0xc0ac29b7c97c50dd,
    0x3f84d5b5b5470917,
    0x9216d5d98979fb1b
]

MANTIS_ALPHA = 0x243f6a8885a308d3

MANTIS_SBOX = [0xC, 0xA, 0xD, 0x3, 0xE, 0xB, 0xF, 0x7,
               0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]

TWEAK_PERMUTATION = [6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11]
TWEAK_PERMUTATION_INV = [4, 5, 6, 7, 11, 1, 0, 8, 12, 13, 14, 15, 9, 10, 2, 3]

CELL_PERMUTATION = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2]
CELL_PERMUTATION_INV = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12]

MIDORI_M = [[0, 1, 1, 1], [1, 0, 1, 1], [1, 1, 0, 1], [1, 1, 1, 0]]


class MantisBlockCipher(Cipher):

    """
    Return a cipher object of the MANTIS Block Cipher.

    The MANTIS cipher is a lightweight tweakable block cipher designed for low-latency applications.
    It operates on 64-bit blocks with a 128-bit key and a 64-bit tweak.
    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `6`);
      number of rounds of the cipher. Must be one of [5, 6, 7, 8].

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.mantis_block_cipher import MantisBlockCipher
        sage: mantis = MantisBlockCipher(number_of_rounds=6)
        sage: plaintext = 0xd6522035c1c0c6c1
        sage: key = 0x92f09952c625e3e9d7a060f714c0292b
        sage: tweak = 0xba912e6f1055fed2
        sage: ciphertext = 0x60e43457311936fd
        sage: mantis.evaluate([plaintext, key, tweak]) == ciphertext
        True
    """

    def __init__(self, number_of_rounds=6):
        self.block_bit_size = 64
        self.key_bit_size = 128
        self.tweak_bit_size = 64

        super().__init__(
            family_name="mantis",
            cipher_type="block_cipher",
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY, INPUT_TWEAK],
            cipher_inputs_bit_size=[
                self.block_bit_size,
                self.key_bit_size,
                self.tweak_bit_size],
            cipher_output_bit_size=self.block_bit_size
        )
        self.add_round()
        current_state = self.add_pre_whitening()
        current_state, current_tweak = self.add_forward_rounds(
            current_state, number_of_rounds)
        current_state = self.add_middle_layer(current_state)
        current_state, current_tweak = self.add_backward_rounds(
            current_state, number_of_rounds, current_tweak)
        ciphertext = self.add_post_whitening(current_state, current_tweak)
        self.add_cipher_output_component(
            [ciphertext], [list(range(64))], 64)

    def apply_sbox_layer(self, current_state):
        sbox_id_list = []
        sbox_bit_positions = []
        for i in range(16):
            data_id_list, data_bit_positions = extract_inputs(
                [current_state], [list(range(64))], list(range(i * 4, (i + 1) * 4)))
            sbox_output = self.add_SBOX_component(
                data_id_list, data_bit_positions, 4, MANTIS_SBOX)
            sbox_id_list.append(sbox_output.id)
            sbox_bit_positions.append(list(range(4)))

        zero_constant = self.add_constant_component(64, 0)
        concatenated_state = self.add_XOR_component(
            sbox_id_list + [zero_constant.id],
            sbox_bit_positions + [list(range(64))],
            64
        )
        return concatenated_state.id

    def add_round_constant(self, sbox_id_list, sbox_bit_positions, round_idx):
        constant = self.add_constant_component(
            64, MANTIS_ROUND_CONSTANTS[round_idx])
        constant_xor = self.add_XOR_component(
            sbox_id_list + [constant.id],
            sbox_bit_positions + [list(range(64))],
            64
        )
        return constant_xor.id

    def add_tweakey(self, current_tweak):
        permuted_tweak = self.add_word_permutation_component(
            [current_tweak], [list(range(64))], 64, TWEAK_PERMUTATION, 4
        ).id

        tweakey = self.add_XOR_component(
            [permuted_tweak, INPUT_KEY],
            [list(range(64)), list(range(64, 128))], 64
        )
        return tweakey.id, permuted_tweak

    def permute_cells(self, current_state):
        permuted_state = self.add_word_permutation_component(
            [current_state], [list(range(64))], 64, CELL_PERMUTATION, 4
        )
        return permuted_state.id

    def apply_mixcolumns(self, current_state):
        column_size = 16
        num_columns = 4

        groups = []
        for col in range(num_columns):
            indices = []
            for row in range(num_columns):
                nibble_index = row * 4 + col
                start_bit = nibble_index * 4
                indices.extend(range(start_bit, start_bit + 4))
            groups.append(indices)

        mix_column_ids = []
        for i in range(num_columns):
            data_id_list, data_bit_positions = extract_inputs(
                [current_state], [list(range(64))], groups[i])

            mix_output = self.add_mix_column_component(
                data_id_list, data_bit_positions, column_size, [
                    MIDORI_M, 19, 4]
            )
            mix_column_ids.append(mix_output.id)

        zero_constant = self.add_constant_component(64, 0)
        concatenated_state = self.add_XOR_component(
            mix_column_ids + [zero_constant.id],
            [list(range(column_size))
             for _ in range(num_columns)] + [list(range(64))],
            64
        )

        column_to_row_permutation = [
            0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
        ]
        mixed_state = self.add_word_permutation_component(
            [concatenated_state.id], [
                list(range(64))], 64, column_to_row_permutation, 4
        )
        return mixed_state.id

    def permute_cells_inverse(self, current_state):
        permuted_state = self.add_word_permutation_component(
            [current_state], [list(range(64))], 64, CELL_PERMUTATION_INV, 4
        )
        return permuted_state.id

    def add_tweakey_backward(
            self, current_state, current_tweak, round_idx, num_rounds):
        if round_idx != num_rounds - 1:
            current_tweak = self.add_word_permutation_component(
                [current_tweak],
                [list(range(64))],
                64,
                TWEAK_PERMUTATION_INV,
                4
            ).id
        alpha_component = self.add_constant_component(64, MANTIS_ALPHA)
        k1_xor_alpha = self.add_XOR_component(
            [INPUT_KEY, alpha_component.id],
            [list(range(64, 128)), list(range(64))],
            64
        )
        tweakey = self.add_XOR_component(
            [current_tweak, k1_xor_alpha.id],
            [list(range(64)), list(range(64))],
            64
        )
        result = self.add_XOR_component(
            [current_state, tweakey.id],
            [list(range(64)), list(range(64))],
            64
        )
        return result.id, current_tweak

    def add_round_constant_direct(self, current_state, round_idx):
        constant = self.add_constant_component(
            64, MANTIS_ROUND_CONSTANTS[round_idx])
        constant_xor = self.add_XOR_component(
            [current_state, constant.id],
            [list(range(64)), list(range(64))],
            64
        )
        return constant_xor.id

    def add_pre_whitening(self):
        k1_xor_tweak = self.add_XOR_component(
            [INPUT_KEY, INPUT_TWEAK], [list(range(64, 128)), list(range(64))], 64)
        m_xor_k0 = self.add_XOR_component([INPUT_PLAINTEXT, INPUT_KEY], [
                                          list(range(64)), list(range(64))], 64)
        pre_whitening = self.add_XOR_component([m_xor_k0.id, k1_xor_tweak.id], [
                                               list(range(64)), list(range(64))], 64)
        return pre_whitening.id

    def add_forward_rounds(self, current_state, num_rounds):
        current_tweak = INPUT_TWEAK

        for round_idx in range(num_rounds):
            sbox_id_list = []
            sbox_bit_positions = []
            for i in range(16):
                data_id_list, data_bit_positions = extract_inputs(
                    [current_state], [list(range(64))], list(range(i * 4, (i + 1) * 4)))
                sbox_output = self.add_SBOX_component(
                    data_id_list, data_bit_positions, 4, MANTIS_SBOX)
                sbox_id_list.append(sbox_output.id)
                sbox_bit_positions.append(list(range(4)))

            current_state = self.add_round_constant(
                sbox_id_list, sbox_bit_positions, round_idx)

            tweakey_id, current_tweak = self.add_tweakey(current_tweak)
            current_state = self.add_XOR_component(
                [current_state, tweakey_id],
                [list(range(64)), list(range(64))], 64
            ).id

            current_state = self.permute_cells(current_state)

            current_state = self.apply_mixcolumns(current_state)

            self.add_round_output_component(
                [current_state], [list(range(64))], 64)
            self.add_round()

        return current_state, current_tweak

    def add_middle_layer(self, current_state):
        current_state = self.apply_sbox_layer(current_state)

        current_state = self.apply_mixcolumns(current_state)

        current_state = self.apply_sbox_layer(current_state)

        return current_state

    def add_backward_rounds(self, current_state, num_rounds, current_tweak):
        for round_idx in range(num_rounds - 1, -1, -1):
            current_state = self.apply_mixcolumns(current_state)

            current_state = self.permute_cells_inverse(current_state)

            current_state, current_tweak = self.add_tweakey_backward(
                current_state, current_tweak, round_idx, num_rounds
            )

            current_state = self.add_round_constant_direct(
                current_state, round_idx)

            current_state = self.apply_sbox_layer(current_state)

            self.add_round_output_component(
                [current_state], [list(range(64))], 64)

            if round_idx != 0:
                self.add_round()

        return current_state, current_tweak

    def add_post_whitening(self, current_state, current_tweak):
        current_tweak = self.add_word_permutation_component(
            [current_tweak],
            [list(range(64))],
            64,
            TWEAK_PERMUTATION_INV,
            4
        ).id
        k0_rot1 = self.add_rotate_component(
            [INPUT_KEY], [list(range(64))], 64, 1
        )
        k0_sh63 = self.add_SHIFT_component(
            [INPUT_KEY], [list(range(64))], 64, 63
        )
        k0_prime = self.add_XOR_component(
            [k0_rot1.id, k0_sh63.id],
            [list(range(64)), list(range(64))],
            64
        )
        alpha_component = self.add_constant_component(64, MANTIS_ALPHA)
        k1_xor_alpha = self.add_XOR_component(
            [INPUT_KEY, alpha_component.id],
            [list(range(64, 128)), list(range(64))],
            64
        )

        k1_alpha_xor_tweak = self.add_XOR_component(
            [k1_xor_alpha.id, current_tweak],
            [list(range(64)), list(range(64))],
            64
        )
        state_xor_tweakey = self.add_XOR_component(
            [current_state, k1_alpha_xor_tweak.id],
            [list(range(64)), list(range(64))],
            64
        )
        post_whitening = self.add_XOR_component(
            [state_xor_tweakey.id, k0_prime.id],
            [list(range(64)), list(range(64))],
            64
        )

        return post_whitening.id
