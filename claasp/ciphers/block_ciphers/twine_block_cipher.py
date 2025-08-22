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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

input_types = [INPUT_KEY, INPUT_PLAINTEXT]
PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64, "key_bit_size": 80, "number_of_rounds": 36},
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 36},
]


def get_word_bit_indexes(word_index):
    return list(range(word_index * 4, word_index * 4 + 4))


class TwineBlockCipher(Cipher):
    """
    Construct an instance of the TwineBlockCipher class, based on the specifications (available at
    https://www.nec.com/en/global/rd/tg/code/symenc/pdf/twine_LC11.pdf).


    This class is used to store compact representations of a cipher,
    used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `80`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `36`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``sub_keys_zero`` -- **boolean** (default: `False`)
    - ``transformations_flag`` -- **boolean** (default: `True`)

    EXAMPLES::

        # Test vectors taken from the specifications, Table 11, available at
        # https://www.nec.com/en/global/rd/tg/code/symenc/pdf/twine_LC11.pdf

        sage: from claasp.ciphers.block_ciphers.twine_block_cipher import TwineBlockCipher
        sage: twine = TwineBlockCipher(key_bit_size=80, number_of_rounds=36)
        sage: twine.evaluate([0x123456789ABCDEF,0x00112233445566778899]) == 0x7C1F0F80B1DF9C28
        True

        sage: from claasp.ciphers.block_ciphers.twine_block_cipher import TwineBlockCipher
        sage: twine = TwineBlockCipher(key_bit_size=128, number_of_rounds=36)
        sage: twine.evaluate([0x123456789ABCDEF,0x00112233445566778899AABBCCDDEEFF]) == 0x979FF9B379B5A9B8
        True
    """

    def __init__(self, key_bit_size=80, number_of_rounds=36):
        self.block_bit_size = 64
        if key_bit_size not in [80, 128]:
            raise ValueError("Incorrect value for key_bit_size (should be in [80, 128])")
        self.key_bit_size = key_bit_size
        self.sbox = [0xC, 0x0, 0xF, 0xA, 0x2, 0xB, 0x9, 0x5, 0x8, 0x3, 0xD, 0x7, 0x1, 0xE, 0x6, 0x4]
        # fmt: off
        self.round_constants = [
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x23, 0x05, 0x0A,
            0x14, 0x28, 0x13, 0x26, 0x0F, 0x1E, 0x3C, 0x3B, 0x35, 0x29, 0x11, 0x22, 0x07, 0x0E,
            0x1C, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24, 0x0B
        ]
        # fmt: on
        self.permutation = [0x5, 0x0, 0x1, 0x4, 0x7, 0xC, 0x3, 0x8, 0xD, 0x6, 0x9, 0x2, 0xF, 0xA, 0xB, 0xE]
        self.permutation_inv = [0x1, 0x2, 0xB, 0x6, 0x3, 0x0, 0x9, 0x4, 0x7, 0xA, 0xD, 0xE, 0x5, 0x8, 0xF, 0xC]

        super().__init__(
            family_name="twine",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        state = INPUT_PLAINTEXT
        key = INPUT_KEY
        if self.key_bit_size == 80:
            subkey_order = [1, 3, 4, 6, 13, 14, 15, 16]
        else:
            subkey_order = [2, 3, 12, 15, 17, 18, 28, 31]

        for round_i in range(1, number_of_rounds + 1):
            self.add_round()
            round_key = self.add_round_key_output_component(
                [key], [[j for i in subkey_order for j in get_word_bit_indexes(i)]], 32
            ).id
            state = self.round_function(state, round_key)
            key = self.update_key(key, round_i)
        self.add_cipher_output_component(
            [state], [[_ for i in range(16) for _ in get_word_bit_indexes(self.permutation[i])]], 64
        )

    def update_key(self, k, i):
        def update_word(emitting_word_indx, receiving_word_indx):
            sbox = self.add_SBOX_component([k], [get_word_bit_indexes(emitting_word_indx)], 4, self.sbox).id
            return self.add_XOR_component([sbox, k], [list(range(4)), get_word_bit_indexes(receiving_word_indx)], 4).id

        xor0 = update_word(0, 1)
        xor1 = update_word(16, 4)

        c0 = self.add_constant_component(6, self.round_constants[i - 1]).id
        pad = self.add_constant_component(1, 0b0).id
        xor_c0 = self.add_XOR_component([pad, c0, k], [[0], list(range(3)), get_word_bit_indexes(7)], 4).id
        xor_c1 = self.add_XOR_component([pad, c0, k], [[0], list(range(3, 6)), get_word_bit_indexes(19)], 4).id

        if self.key_bit_size == 80:
            input_ids = [xor1, k, xor_c0, k, xor_c1, xor0, k]
            input_bit_positions = [
                list(range(4)),
                list(range(20, 28)),
                list(range(4)),
                list(range(32, 76)),
                list(range(4)),
                list(range(4)),
                list(range(8, 16)) + list(range(4)),
            ]
        else:
            xor2 = update_word(30, 23)
            input_ids = [xor1, k, xor_c0, k, xor_c1, k, xor2, k, xor0, k]
            input_bit_positions = [
                list(range(4)),
                list(range(20, 28)),
                list(range(4)),
                list(range(32, 76)),
                list(range(4)),
                list(range(80, 92)),
                list(range(4)),
                list(range(96, 128)),
                list(range(4)),
                list(range(8, 16)) + list(range(4)),
            ]

        updated_key = self.add_intermediate_output_component(
            input_ids, input_bit_positions, self.key_bit_size, "updated_key"
        )

        return updated_key.id

    def round_function(self, x, k):
        sb_order = [0, 5, 1, 4, 3, 6, 2, 7]
        after_key_add = self.add_XOR_component(
            [x, k], [[_ for i in range(8) for _ in get_word_bit_indexes(2 * i)], list(range(32))], 32
        ).id
        sb_outputs = [
            self.add_SBOX_component([after_key_add], [get_word_bit_indexes(i)], 4, self.sbox).id for i in range(8)
        ]
        xor_outputs = [
            self.add_XOR_component([sb_outputs[i], x], [list(range(4))] + [get_word_bit_indexes(2 * i + 1)], 4).id
            for i in sb_order
        ]
        round_output = self.add_round_output_component(
            [_ for xor in xor_outputs for _ in (xor, x)],
            [_ for i in range(8) for _ in (list(range(4)), get_word_bit_indexes(self.permutation_inv[2 * i + 1]))],
            64,
        ).id

        return round_output
