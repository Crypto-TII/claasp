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


PARAMETERS_CONFIGURATION_LIST = [
    {'block_bit_size': 128, 'key_bit_size': 128},
    {'block_bit_size': 128, 'key_bit_size': 192},
    {'block_bit_size': 128, 'key_bit_size': 256},
]


class RijndaelBlockCipher(Cipher):
    """
    Return a cipher object of Rijndael Block Cipher.

    Rijndael is the algorithm that became AES. This implementation supports
    the standard AES configurations (128-bit block size).

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `128`); block size in bits (must be 128)
    - ``key_bit_size`` -- **integer** (default: `128`); key size in bits (128, 192, or 256)

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.rijndael_block_cipher import RijndaelBlockCipher
        sage: # Rijndael-128 with 128-bit key (AES-128)
        sage: rijndael = RijndaelBlockCipher(block_bit_size=128, key_bit_size=128)
        sage: key = 0x2b7e151628aed2a6abf7158809cf4f3c
        sage: plaintext = 0x3243f6a8885a308d313198a2e0370734
        sage: rijndael.evaluate([key, plaintext]) == 0x3925841d02dc09fbdc118597196a0b32
        True

        sage: # Rijndael with different parameters
        sage: rijndael_256 = RijndaelBlockCipher(block_bit_size=128, key_bit_size=256)
        sage: rijndael_192 = RijndaelBlockCipher(block_bit_size=128, key_bit_size=192)

    """

    def __init__(self, block_bit_size=128, key_bit_size=128):
        if block_bit_size != 128:
            raise ValueError(f"block_bit_size must be 128, got {block_bit_size}")
        if key_bit_size not in [128, 192, 256]:
            raise ValueError(f"key_bit_size must be one of [128, 192, 256], got {key_bit_size}")

        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size

        # Rijndael parameters for 128-bit block
        self.nk = key_bit_size // 32  # Number of key words (Nk)
        self.nr = self.nk + 6  # Number of rounds (Nr = Nk + 6)

        # S-box LUT from Rijndael specification
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
        ]

        # Round constants for key expansion
        self.rc = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

        # Mix column coefficient matrix and polynomial for GF(2^8)
        self.mix_col_matrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        self.mix_col_desc = [self.mix_col_matrix, 0x11b, 8]  # Matrix, polynomial, element size

        super().__init__(
            family_name="rijndael",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[key_bit_size, block_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        self.key_words = {}
        self._build_cipher()

    def _build_cipher(self):
        """Build the complete cipher with all rounds."""
        state = ComponentState([INPUT_PLAINTEXT], [list(range(self.block_bit_size))])

        for round_number in range(self.nr):
            self.add_round()

            if round_number == 0:
                # Initial round: generate key schedule and AddRoundKey (whitening)
                self._generate_key_schedule()
                round_key = self._get_round_key(0)
                state = self._add_round_key(state, round_key)

            # SubByte transformation
            state = self._apply_subbyte(state)

            # ShiftRow transformation
            state = self._apply_shiftrow(state)

            # MixColumn transformation (except in final round)
            if round_number < self.nr - 1:
                state = self._apply_mixcolumn(state)

            # AddRoundKey
            round_key = self._get_round_key(round_number + 1)
            state = self._add_round_key(state, round_key)

            # Output component
            if round_number == self.nr - 1:
                # Final round: output ciphertext
                self.add_cipher_output_component(state.id, state.input_bit_positions, self.block_bit_size)
            else:
                # Intermediate round: add round output
                self.add_round_output_component(state.id, state.input_bit_positions, self.block_bit_size)

    def _generate_key_schedule(self):
        """Generate all key words for all rounds."""
        # Extract initial key words from INPUT_KEY: w[0] ... w[Nk-1]
        for w in range(self.nk):
            key_word = ComponentState([INPUT_KEY], [list(range(w * 32, (w + 1) * 32))])
            self.key_words[w] = key_word

        # Generate remaining key words
        total_words = 4 * (self.nr + 1)

        for w in range(self.nk, total_words):
            prev_word = self.key_words[w - 1]

            if w % self.nk == 0:
                # RotWord: rotate right by 1 byte (8 bits)
                rotated = self.add_rotate_component(prev_word.id, prev_word.input_bit_positions, 32, -8)
                temp_state = ComponentState([self.get_current_component_id()], [list(range(32))])

                # SubWord: apply S-box to each byte
                sub_state = self._apply_subbyte_to_word(temp_state)

                # XOR with Rcon
                rcon_idx = (w // self.nk) - 1
                rcon_value = self.rc[rcon_idx] << 24
                rcon_comp = self.add_constant_component(32, rcon_value)
                
                temp = self.add_XOR_component(
                    sub_state.id + [rcon_comp.id],
                    sub_state.input_bit_positions + [list(range(32))],
                    32
                )
                temp_state = ComponentState([self.get_current_component_id()], [list(range(32))])

            elif self.nk > 6 and w % self.nk == 4:
                # For 256-bit keys: apply SubWord to w[i-1]
                temp_state = self._apply_subbyte_to_word(prev_word)

            else:
                # No transformation: temp = w[i-1]
                temp_state = prev_word

            # w[i] = w[i-Nk] XOR temp
            word_minus_nk = self.key_words[w - self.nk]
            new_word = self.add_XOR_component(
                word_minus_nk.id + temp_state.id,
                word_minus_nk.input_bit_positions + temp_state.input_bit_positions,
                32
            )
            self.key_words[w] = ComponentState([self.get_current_component_id()], [list(range(32))])

    def _apply_subbyte_to_word(self, word_state):
        """Apply S-box to each byte of a 32-bit word and concatenate."""
        sbox_outputs = []
        for byte_idx in range(4):
            byte_start = byte_idx * 8
            byte_end = byte_start + 8
            sbox_out = self.add_SBOX_component(
                word_state.id,
                [list(range(byte_start, byte_end))],
                8,
                self.sbox
            )
            sbox_outputs.append(sbox_out)

        # Concatenate by XORing (since all outputs are independent 8-bit pieces)
        combined = self.add_XOR_component(
            [s.id for s in sbox_outputs],
            [list(range(8)) for _ in sbox_outputs],
            32
        )
        return ComponentState([self.get_current_component_id()], [list(range(32))])

    def _get_round_key(self, round_number):
        """Get the 128-bit round key (concatenate 4 key words)."""
        round_key_ids = []
        round_key_bits = []

        for col in range(4):
            word_idx = round_number * 4 + col
            word_state = self.key_words[word_idx]
            round_key_ids.extend(word_state.id)
            round_key_bits.extend(word_state.input_bit_positions)

        return ComponentState(round_key_ids, round_key_bits)

    def _add_round_key(self, state, round_key):
        """XOR the state with the round key."""
        xor_result = self.add_XOR_component(
            state.id + round_key.id,
            state.input_bit_positions + round_key.input_bit_positions,
            self.block_bit_size
        )
        return ComponentState([self.get_current_component_id()], [list(range(self.block_bit_size))])

    def _apply_subbyte(self, state):
        """Apply SubByte transformation (S-box on all 16 bytes)."""
        sbox_outputs = []
        for byte_idx in range(16):
            byte_start = byte_idx * 8
            byte_end = byte_start + 8
            sbox_out = self.add_SBOX_component(
                state.id,
                [list(range(byte_start, byte_end))],
                8,
                self.sbox
            )
            sbox_outputs.append(sbox_out)

        # Concatenate all outputs
        combined = self.add_XOR_component(
            [s.id for s in sbox_outputs],
            [list(range(8)) for _ in sbox_outputs],
            self.block_bit_size
        )
        return ComponentState([self.get_current_component_id()], [list(range(self.block_bit_size))])

    def _apply_shiftrow(self, state):
        """Apply ShiftRow transformation."""
        # Rijndael state is organized as 4x4 bytes in column-major order
        # ShiftRow shifts each row cyclically:
        # Row 0: no shift
        # Row 1: shift left by 1
        # Row 2: shift left by 2
        # Row 3: shift left by 3
        
        # Build the permuted byte order
        permuted_bits = []
        for row in range(4):
            for col in range(4):
                # Original column-major index
                orig_col = (col - row) % 4
                byte_idx = orig_col * 4 + row
                byte_start = byte_idx * 8
                byte_end = byte_start + 8
                permuted_bits.append(list(range(byte_start, byte_end)))

        # Use intermediate output to perform the permutation
        shift_result = self.add_intermediate_output_component(
            [state.id[0]] * 16,
            permuted_bits,
            self.block_bit_size,
            "shift_rows"
        )
        return ComponentState([self.get_current_component_id()], [list(range(self.block_bit_size))])

    def _apply_mixcolumn(self, state):
        """Apply MixColumn transformation on all columns."""
        column_outputs = []
        for col in range(4):
            col_start = col * 32
            col_end = col_start + 32

            # Apply mix_column component for this column
            mixed = self.add_mix_column_component(
                [state.id[0]],
                [list(range(col_start, col_end))],
                32,
                self.mix_col_desc
            )
            column_outputs.append(mixed)

        # Concatenate mixed columns
        mixed_result = self.add_XOR_component(
            [c.id for c in column_outputs],
            [list(range(32)) for _ in column_outputs],
            self.block_bit_size
        )
        return ComponentState([self.get_current_component_id()], [list(range(self.block_bit_size))])
