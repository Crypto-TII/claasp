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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 128, 'key_bit_size': 128, 'number_of_rounds': 10},
    {'block_bit_size': 128, 'key_bit_size': 160, 'number_of_rounds': 11},
    {'block_bit_size': 128, 'key_bit_size': 192, 'number_of_rounds': 12},
    {'block_bit_size': 128, 'key_bit_size': 224, 'number_of_rounds': 13},
    {'block_bit_size': 128, 'key_bit_size': 256, 'number_of_rounds': 14},
    {'block_bit_size': 160, 'key_bit_size': 128, 'number_of_rounds': 11},
    {'block_bit_size': 160, 'key_bit_size': 160, 'number_of_rounds': 11},
    {'block_bit_size': 160, 'key_bit_size': 192, 'number_of_rounds': 12},
    {'block_bit_size': 160, 'key_bit_size': 224, 'number_of_rounds': 13},
    {'block_bit_size': 160, 'key_bit_size': 256, 'number_of_rounds': 14},
    {'block_bit_size': 192, 'key_bit_size': 128, 'number_of_rounds': 12},
    {'block_bit_size': 192, 'key_bit_size': 160, 'number_of_rounds': 12},
    {'block_bit_size': 192, 'key_bit_size': 192, 'number_of_rounds': 12},
    {'block_bit_size': 192, 'key_bit_size': 224, 'number_of_rounds': 13},
    {'block_bit_size': 192, 'key_bit_size': 256, 'number_of_rounds': 14},
    {'block_bit_size': 224, 'key_bit_size': 128, 'number_of_rounds': 13},
    {'block_bit_size': 224, 'key_bit_size': 160, 'number_of_rounds': 13},
    {'block_bit_size': 224, 'key_bit_size': 192, 'number_of_rounds': 13},
    {'block_bit_size': 224, 'key_bit_size': 224, 'number_of_rounds': 13},
    {'block_bit_size': 224, 'key_bit_size': 256, 'number_of_rounds': 14},
    {'block_bit_size': 256, 'key_bit_size': 128, 'number_of_rounds': 14},
    {'block_bit_size': 256, 'key_bit_size': 160, 'number_of_rounds': 14},
    {'block_bit_size': 256, 'key_bit_size': 192, 'number_of_rounds': 14},
    {'block_bit_size': 256, 'key_bit_size': 224, 'number_of_rounds': 14},
    {'block_bit_size': 256, 'key_bit_size': 256, 'number_of_rounds': 14},
]


class RijndaelBlockCipher(Cipher):
    """
    Return a cipher object of Rijndael Block Cipher.

    The implementation follows the Rijndael terminology used in the main
    references: the state has 4 rows and ``state_columns`` columns, the key
    schedule has ``key_columns`` words, and the number of rounds is
    ``max(state_columns, key_columns) + 6``. Internally the construction uses
    ``ComponentState`` objects to keep the state and key words explicit.

    REFERENCES:

    Daemen, J., & Rijmen, V. (2002). A Specification for Rijndael, the AES
    Algorithm. https://asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
    [RijndaelSpec]_.

    Daemen, J., & Rijmen, V. (2001). The Design of Rijndael AES -- The
    Advanced Encryption Standard.
    https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf [RijndaelDesign]_.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`); block size in bits
      (128, 160, 192, 224, or 256)
    - ``key_bit_size`` -- **integer** (default: `128`); key size in bits
      (128, 160, 192, 224, or 256)
    - ``number_of_rounds`` -- **integer** (default: computed from block/key
      sizes); override for the number of rounds

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.rijndael_block_cipher import RijndaelBlockCipher
        sage: rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=128)
        sage: key = 0x2b7e151628aed2a6abf7158809cf4f3c
        sage: plaintext = 0x3243f6a8885a308d313198a2e0370734
        sage: ciphertext = 0x3925841d02dc09fbdc118597196a0b32
        sage: rijndael.evaluate([key, plaintext]) == ciphertext
        True

        sage: from random import Random
        sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
        sage: samples = Random(int(20260326))
        sage: for key_bit_size in (128, 192, 256):
        ....:     aes = AESBlockCipher(key_bit_size=key_bit_size)
        ....:     rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=key_bit_size)
        ....:     key = samples.getrandbits(key_bit_size)
        ....:     plaintext = samples.getrandbits(128)
        ....:     aes.evaluate([key, plaintext]) == rijndael.evaluate([key, plaintext])
        True
        True
        True
    """

    def __init__(self, block_bit_size=128, key_bit_size=128, number_of_rounds=None):
        valid_sizes = [128, 160, 192, 224, 256]
        if block_bit_size not in valid_sizes:
            raise ValueError(f"block_bit_size must be one of {valid_sizes}, got {block_bit_size}")
        if key_bit_size not in valid_sizes:
            raise ValueError(f"key_bit_size must be one of {valid_sizes}, got {key_bit_size}")

        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.state_rows = 4
        self.word_bit_size = 32
        self.byte_bit_size = 8
        self.state_columns = block_bit_size // self.word_bit_size
        self.key_columns = key_bit_size // self.word_bit_size
        self.rounds_count = max(self.state_columns, self.key_columns) + 6
        if number_of_rounds is not None:
            self.rounds_count = number_of_rounds

        super().__init__(
            family_name="rijndael",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[key_bit_size, block_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        self.row_shifts = self._get_row_shifts(self.state_columns)
        self.sbox_lookup_table = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
        ]
        self.mix_column_description = [
            [
                [0x02, 0x03, 0x01, 0x01],
                [0x01, 0x02, 0x03, 0x01],
                [0x01, 0x01, 0x02, 0x03],
                [0x03, 0x01, 0x01, 0x02],
            ],
            0x11B,
            self.byte_bit_size,
        ]
        self.round_constants = self._generate_round_constants()
        self.key_words = {}

        self._build_cipher()

    def _build_cipher(self):
        state = ComponentState([INPUT_PLAINTEXT], [list(range(self.block_bit_size))])

        for round_index in range(self.rounds_count):
            self.add_round()

            if round_index == 0:
                self._expand_key_schedule()
                initial_round_key = self._get_round_key_state(0)
                state = self._add_round_key(state, initial_round_key)

            state = self._sub_bytes(state)
            state = self._shift_rows(state)

            if round_index < self.rounds_count - 1:
                state = self._mix_columns(state)

            round_key = self._get_round_key_state(round_index + 1)
            state = self._add_round_key(state, round_key)
            self._emit_round_key_output(round_key)

            if round_index == self.rounds_count - 1:
                self._emit_cipher_output(state)
            else:
                self._emit_round_output(state)

    def _expand_key_schedule(self):
        total_words = self.state_columns * (self.rounds_count + 1)
        for word_index in range(self.key_columns):
            start_bit = word_index * self.word_bit_size
            self.key_words[word_index] = ComponentState(
                [INPUT_KEY],
                [[start_bit + bit for bit in range(self.word_bit_size)]],
            )

        for word_index in range(self.key_columns, total_words):
            self.key_words[word_index] = self._generate_key_word(word_index)

    def _generate_key_word(self, word_index):
        temp_word = self.key_words[word_index - 1]

        if word_index % self.key_columns == 0:
            temp_word = self._xor_word_with_constant(
                self._sub_word(self._rotate_word(temp_word)),
                self.round_constants[(word_index // self.key_columns) - 1],
            )
        elif self.key_columns > 6 and word_index % self.key_columns == 4:
            temp_word = self._sub_word(temp_word)

        return self._xor_words(self.key_words[word_index - self.key_columns], temp_word)

    def _get_round_key_state(self, round_index):
        start_word_index = round_index * self.state_columns
        round_key_words = [
            self.key_words[start_word_index + offset]
            for offset in range(self.state_columns)
        ]
        return ComponentState(
            [word.id[0] for word in round_key_words],
            [word.input_bit_positions[0] for word in round_key_words],
        )

    def _rotate_word(self, word_state):
        rotated_word = self.add_rotate_component(
            word_state.id,
            word_state.input_bit_positions,
            self.word_bit_size,
            -self.byte_bit_size,
        )
        return ComponentState([rotated_word.id], [list(range(self.word_bit_size))])

    def _sub_word(self, word_state):
        substituted_bytes = []
        for byte_index in range(4):
            byte_start = byte_index * self.byte_bit_size
            substituted_bytes.append(
                self.add_sbox_component(
                    word_state.id,
                    [list(range(byte_start, byte_start + self.byte_bit_size))],
                    self.byte_bit_size,
                    self.sbox_lookup_table,
                )
            )

        substituted_word = self.add_intermediate_output_component(
            [component.id for component in substituted_bytes],
            [list(range(self.byte_bit_size)) for _ in substituted_bytes],
            self.word_bit_size,
            "sub_word",
        )
        return ComponentState([substituted_word.id], [list(range(self.word_bit_size))])

    def _xor_word_with_constant(self, word_state, constant_value):
        constant_component = self.add_constant_component(self.word_bit_size, constant_value)
        xor_component = self.add_xor_component(
            word_state.id + [constant_component.id],
            word_state.input_bit_positions + [list(range(self.word_bit_size))],
            self.word_bit_size,
        )
        return ComponentState([xor_component.id], [list(range(self.word_bit_size))])

    def _xor_words(self, left_word, right_word):
        xor_component = self.add_xor_component(
            left_word.id + right_word.id,
            left_word.input_bit_positions + right_word.input_bit_positions,
            self.word_bit_size,
        )
        return ComponentState([xor_component.id], [list(range(self.word_bit_size))])

    def _sub_bytes(self, state):
        substituted_bytes = []
        for column_index in range(self.state_columns):
            for row_index in range(self.state_rows):
                byte_index = column_index * self.state_rows + row_index
                byte_start = byte_index * self.byte_bit_size
                substituted_bytes.append(
                    self.add_sbox_component(
                        state.id,
                        [list(range(byte_start, byte_start + self.byte_bit_size))],
                        self.byte_bit_size,
                        self.sbox_lookup_table,
                    )
                )

        substituted_state = self.add_intermediate_output_component(
            [component.id for component in substituted_bytes],
            [list(range(self.byte_bit_size)) for _ in substituted_bytes],
            self.block_bit_size,
            "sub_bytes",
        )
        return ComponentState([substituted_state.id], [list(range(self.block_bit_size))])

    def _shift_rows(self, state):
        shifted_bit_positions = []
        for column_index in range(self.state_columns):
            for row_index in range(self.state_rows):
                source_column = (column_index + self.row_shifts[row_index]) % self.state_columns
                byte_index = source_column * self.state_rows + row_index
                byte_start = byte_index * self.byte_bit_size
                shifted_bit_positions.append(list(range(byte_start, byte_start + self.byte_bit_size)))

        shifted_state = self.add_intermediate_output_component(
            [state.id[0]] * self.state_rows * self.state_columns,
            shifted_bit_positions,
            self.block_bit_size,
            "shift_rows",
        )
        return ComponentState([shifted_state.id], [list(range(self.block_bit_size))])

    def _mix_columns(self, state):
        mixed_columns = []
        for column_index in range(self.state_columns):
            bit_start = column_index * self.word_bit_size
            mixed_columns.append(
                self.add_mix_column_component(
                    state.id,
                    [list(range(bit_start, bit_start + self.word_bit_size))],
                    self.word_bit_size,
                    self.mix_column_description,
                )
            )

        mixed_state = self.add_intermediate_output_component(
            [component.id for component in mixed_columns],
            [list(range(self.word_bit_size)) for _ in mixed_columns],
            self.block_bit_size,
            "mix_columns",
        )
        return ComponentState([mixed_state.id], [list(range(self.block_bit_size))])

    def _add_round_key(self, state, round_key):
        round_state = self.add_xor_component(
            state.id + round_key.id,
            state.input_bit_positions + round_key.input_bit_positions,
            self.block_bit_size,
        )
        return ComponentState([round_state.id], [list(range(self.block_bit_size))])

    def _emit_round_output(self, state):
        self.add_round_output_component(
            state.id,
            state.input_bit_positions,
            self.block_bit_size,
        )

    def _emit_round_key_output(self, round_key):
        self.add_round_key_output_component(
            round_key.id,
            round_key.input_bit_positions,
            self.block_bit_size,
        )

    def _emit_cipher_output(self, state):
        self.add_cipher_output_component(
            state.id,
            state.input_bit_positions,
            self.block_bit_size,
        )

    @staticmethod
    def _get_row_shifts(state_columns):
        if state_columns in [4, 5, 6]:
            return [0, 1, 2, 3]
        if state_columns == 7:
            return [0, 1, 2, 4]
        if state_columns == 8:
            return [0, 1, 3, 4]
        raise ValueError(f"Unsupported number of state columns: {state_columns}")

    @staticmethod
    def _xtime(byte_value):
        byte_value <<= 1
        if byte_value & 0x100:
            byte_value ^= 0x11B
        return byte_value & 0xFF

    def _generate_round_constants(self):
        round_constants = []
        rc_value = 0x01
        constant_count = self.state_columns * (self.rounds_count + 1) // self.key_columns + 1
        for _ in range(constant_count):
            round_constants.append(rc_value << 24)
            rc_value = self._xtime(rc_value)
        return round_constants
