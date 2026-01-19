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


"""
SKIPJACK block cipher [NIST1998]
https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/skipjack/skipjack.pdf

Cipher Specifications:
- Block size: 64 bits (4 words of 16 bits each)
- Key size: 80 bits (10 bytes)
- Rounds: 32 (alternating Rule A and Rule B)
- Structure:
  * Rounds 1-8: Rule A
  * Rounds 9-16: Rule B
  * Rounds 17-24: Rule A
  * Rounds 25-32: Rule B
"""

from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY


# SKIPJACK F-Table (S-box 8x8 bits)
SKIPJACK_FTABLE = [
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
]


class SkipjackBlockCipher(Cipher):
    """
    SKIPJACK NSA - 64-bit block, 80-bit key, 32 rounds
    
    Based on official CLAASP documentation:
    - add_SBOX_component(input_id_links, input_bit_positions, output_bit_size, description)
    - add_XOR_component(input_id_links, input_bit_positions, output_bit_size)
    - add_concatenate_component(input_id_links, input_bit_positions, output_bit_size)
    
    Where:
    - input_id_links: list of strings ['comp1', 'comp2']
    - input_bit_positions: list of lists [[bits1], [bits2]]
    """

    def __init__(self, number_of_rounds=32):
        self.WORD_SIZE = 16
        self.BLOCK_SIZE = 64
        self.KEY_SIZE = 80

        super().__init__(
            family_name="skipjack",
            cipher_type="block_cipher",
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.BLOCK_SIZE, self.KEY_SIZE],
            cipher_output_bit_size=self.BLOCK_SIZE,
        )

        # Initialize state: w1, w2, w3, w4 from plaintext
        # Plaintext format (big-endian): bits 0-15 (w1), 16-31 (w2), 32-47 (w3), 48-63 (w4)
        w1, w2, w3, w4 = self._initialize_state()

        # 32 rounds
        for round_number in range(number_of_rounds):
            self.add_round()
            counter = round_number + 1

            if (1 <= counter <= 8) or (17 <= counter <= 24):
                # Rule A
                w1, w2, w3, w4 = self._rule_a(w1, w2, w3, w4, counter, round_number)
            else:
                # Rule B
                w1, w2, w3, w4 = self._rule_b(w1, w2, w3, w4, counter, round_number)

            self._add_round_output(w1, w2, w3, w4, round_number, number_of_rounds)

    def _initialize_state(self):
        """
        Extract w1, w2, w3, w4 from plaintext.
        
        Plaintext = 0x33221100ddccbbaa (64 bits)
        Conventional big-endian:
          w1 = 0x3322 (bits 0-15, most significant)
          w2 = 0x1100 (bits 16-31)
          w3 = 0xddcc (bits 32-47)
          w4 = 0xbbaa (bits 48-63, least significant)
        """
        w1 = ComponentState([INPUT_PLAINTEXT], [list(range(0, 16))])
        w2 = ComponentState([INPUT_PLAINTEXT], [list(range(16, 32))])
        w3 = ComponentState([INPUT_PLAINTEXT], [list(range(32, 48))])
        w4 = ComponentState([INPUT_PLAINTEXT], [list(range(48, 64))])
        return w1, w2, w3, w4

    def _g_permutation(self, word, step):
        """
        G function: 4-round Feistel network with F-table SBOX.
        
        Algorithm:
        - Input: 16-bit word
        - g[0] = high byte, g[1] = low byte
        - 4 Feistel rounds: g[i+2] = F[g[i+1] XOR key[j]] XOR g[i]
        - Output: (g[4] << 8) | g[5]
        
        CLAASP convention (big-endian):
        - bits [0:7] = high byte = g[0]
        - bits [8:15] = low byte = g[1]
        """
        # Extract g[0] (high byte, bits 0-7) and g[1] (low byte, bits 8-15)
        g0 = ComponentState(word.id, [word.input_bit_positions[0][0:8]])
        g1 = ComponentState(word.id, [word.input_bit_positions[0][8:16]])

        g_prev = g0  # g[0]
        g_out = g1   # g[1]

        for feistel_round in range(4):
            # Key index: j = (4*step + feistel_round) % 10
            key_index = (4 * step + feistel_round) % 10
            
            # Extract corresponding key byte (KEY = 80 bits, 10 bytes in big-endian)
            # byte[0] = bits 0-7, ..., byte[9] = bits 72-79
            bit_start = key_index * 8
            bit_end = (key_index + 1) * 8
            key_byte = ComponentState([INPUT_KEY], [list(range(bit_start, bit_end))])

            # XOR: g_out XOR key_byte
            self.add_XOR_component(
                [g_out.id[0], key_byte.id[0]],
                [g_out.input_bit_positions[0], key_byte.input_bit_positions[0]],
                8
            )
            xor_result = ComponentState([self.get_current_component_id()], [list(range(8))])

            # SBOX: F[xor_result]
            self.add_SBOX_component(
                [xor_result.id[0]],
                [xor_result.input_bit_positions[0]],
                8,
                SKIPJACK_FTABLE
            )
            sbox_result = ComponentState([self.get_current_component_id()], [list(range(8))])

            # XOR: sbox_result XOR g_prev
            self.add_XOR_component(
                [sbox_result.id[0], g_prev.id[0]],
                [sbox_result.input_bit_positions[0], g_prev.input_bit_positions[0]],
                8
            )
            g_new = ComponentState([self.get_current_component_id()], [list(range(8))])

            # Update for next iteration
            g_prev = g_out
            g_out = g_new

        # At the end: g_prev = g[4], g_out = g[5]
        # Result: (g[4] << 8) | g[5]
        # In CLAASP concatenate: first input goes to MSB (high byte position)
        # So we need: [g[4], g[5]] where g[4] is high byte
        self.add_concatenate_component(
            [g_prev.id[0], g_out.id[0]],
            [g_prev.input_bit_positions[0], g_out.input_bit_positions[0]],
            16
        )
        return ComponentState([self.get_current_component_id()], [list(range(16))])

    def _rule_a(self, w1, w2, w3, w4, counter, round_number):
        """Rule A: w1' = G(w1) XOR w4 XOR counter, w2' = G(w1), w3' = w2, w4' = w3"""
        g_output = self._g_permutation(w1, round_number)

        # Counter
        self.add_constant_component(16, counter)
        counter_comp = ComponentState([self.get_current_component_id()], [list(range(16))])

        # w1' = G(w1) XOR w4 XOR counter
        self.add_XOR_component(
            [g_output.id[0], w4.id[0]],
            [g_output.input_bit_positions[0], w4.input_bit_positions[0]],
            16
        )
        temp = ComponentState([self.get_current_component_id()], [list(range(16))])

        self.add_XOR_component(
            [temp.id[0], counter_comp.id[0]],
            [temp.input_bit_positions[0], counter_comp.input_bit_positions[0]],
            16
        )
        w1_new = ComponentState([self.get_current_component_id()], [list(range(16))])

        return w1_new, g_output, w2, w3

    def _rule_b(self, w1, w2, w3, w4, counter, round_number):
        """Rule B: w1' = w4, w2' = G(w1), w3' = w1 XOR w2 XOR counter, w4' = w3"""
        g_output = self._g_permutation(w1, round_number)

        # Counter
        self.add_constant_component(16, counter)
        counter_comp = ComponentState([self.get_current_component_id()], [list(range(16))])

        # w3' = w1 XOR w2 XOR counter
        self.add_XOR_component(
            [w1.id[0], w2.id[0]],
            [w1.input_bit_positions[0], w2.input_bit_positions[0]],
            16
        )
        temp = ComponentState([self.get_current_component_id()], [list(range(16))])

        self.add_XOR_component(
            [temp.id[0], counter_comp.id[0]],
            [temp.input_bit_positions[0], counter_comp.input_bit_positions[0]],
            16
        )
        w3_new = ComponentState([self.get_current_component_id()], [list(range(16))])

        return w4, g_output, w3_new, w3

    def _add_round_output(self, w1, w2, w3, w4, round_number, total_rounds):
        """Add round output: concatenate w1||w2||w3||w4"""
        self.add_concatenate_component(
            [w1.id[0], w2.id[0], w3.id[0], w4.id[0]],
            [w1.input_bit_positions[0], w2.input_bit_positions[0], w3.input_bit_positions[0], w4.input_bit_positions[0]],
            64
        )
        
        if round_number == total_rounds - 1:
            # Final cipher output
            self.add_cipher_output_component(
                [self.get_current_component_id()],
                [list(range(64))],
                64
            )
        else:
            # Intermediate output
            self.add_round_output_component(
                [self.get_current_component_id()],
                [list(range(64))],
                64
            )
            