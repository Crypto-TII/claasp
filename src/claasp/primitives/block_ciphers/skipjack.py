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
SKIPJACK block primitive [NIST1998]
https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/skipjack/skipjack.pdf

Primitive Specifications:
- Block size: 64 bits (4 words of 16 bits each)
- Key size: 80 bits (10 bytes)
- Rounds: 32 (alternating Rule A and Rule B)
- Structure:
  * Rounds 1-8: Rule A
  * Rounds 9-16: Rule B
  * Rounds 17-24: Rule A
  * Rounds 25-32: Rule B
"""

from claasp.graph.bit_builder import BitGraphPrimitive, BitState
from claasp.primitive_inputs import INPUT_KEY, INPUT_PLAINTEXT

# SKIPJACK F-Table (S-box 8x8 bits)
SKIPJACK_FTABLE = [
    0xA3,
    0xD7,
    0x09,
    0x83,
    0xF8,
    0x48,
    0xF6,
    0xF4,
    0xB3,
    0x21,
    0x15,
    0x78,
    0x99,
    0xB1,
    0xAF,
    0xF9,
    0xE7,
    0x2D,
    0x4D,
    0x8A,
    0xCE,
    0x4C,
    0xCA,
    0x2E,
    0x52,
    0x95,
    0xD9,
    0x1E,
    0x4E,
    0x38,
    0x44,
    0x28,
    0x0A,
    0xDF,
    0x02,
    0xA0,
    0x17,
    0xF1,
    0x60,
    0x68,
    0x12,
    0xB7,
    0x7A,
    0xC3,
    0xE9,
    0xFA,
    0x3D,
    0x53,
    0x96,
    0x84,
    0x6B,
    0xBA,
    0xF2,
    0x63,
    0x9A,
    0x19,
    0x7C,
    0xAE,
    0xE5,
    0xF5,
    0xF7,
    0x16,
    0x6A,
    0xA2,
    0x39,
    0xB6,
    0x7B,
    0x0F,
    0xC1,
    0x93,
    0x81,
    0x1B,
    0xEE,
    0xB4,
    0x1A,
    0xEA,
    0xD0,
    0x91,
    0x2F,
    0xB8,
    0x55,
    0xB9,
    0xDA,
    0x85,
    0x3F,
    0x41,
    0xBF,
    0xE0,
    0x5A,
    0x58,
    0x80,
    0x5F,
    0x66,
    0x0B,
    0xD8,
    0x90,
    0x35,
    0xD5,
    0xC0,
    0xA7,
    0x33,
    0x06,
    0x65,
    0x69,
    0x45,
    0x00,
    0x94,
    0x56,
    0x6D,
    0x98,
    0x9B,
    0x76,
    0x97,
    0xFC,
    0xB2,
    0xC2,
    0xB0,
    0xFE,
    0xDB,
    0x20,
    0xE1,
    0xEB,
    0xD6,
    0xE4,
    0xDD,
    0x47,
    0x4A,
    0x1D,
    0x42,
    0xED,
    0x9E,
    0x6E,
    0x49,
    0x3C,
    0xCD,
    0x43,
    0x27,
    0xD2,
    0x07,
    0xD4,
    0xDE,
    0xC7,
    0x67,
    0x18,
    0x89,
    0xCB,
    0x30,
    0x1F,
    0x8D,
    0xC6,
    0x8F,
    0xAA,
    0xC8,
    0x74,
    0xDC,
    0xC9,
    0x5D,
    0x5C,
    0x31,
    0xA4,
    0x70,
    0x88,
    0x61,
    0x2C,
    0x9F,
    0x0D,
    0x2B,
    0x87,
    0x50,
    0x82,
    0x54,
    0x64,
    0x26,
    0x7D,
    0x03,
    0x40,
    0x34,
    0x4B,
    0x1C,
    0x73,
    0xD1,
    0xC4,
    0xFD,
    0x3B,
    0xCC,
    0xFB,
    0x7F,
    0xAB,
    0xE6,
    0x3E,
    0x5B,
    0xA5,
    0xAD,
    0x04,
    0x23,
    0x9C,
    0x14,
    0x51,
    0x22,
    0xF0,
    0x29,
    0x79,
    0x71,
    0x7E,
    0xFF,
    0x8C,
    0x0E,
    0xE2,
    0x0C,
    0xEF,
    0xBC,
    0x72,
    0x75,
    0x6F,
    0x37,
    0xA1,
    0xEC,
    0xD3,
    0x8E,
    0x62,
    0x8B,
    0x86,
    0x10,
    0xE8,
    0x08,
    0x77,
    0x11,
    0xBE,
    0x92,
    0x4F,
    0x24,
    0xC5,
    0x32,
    0x36,
    0x9D,
    0xCF,
    0xF3,
    0xA6,
    0xBB,
    0xAC,
    0x5E,
    0x6C,
    0xA9,
    0x13,
    0x57,
    0x25,
    0xB5,
    0xE3,
    0xBD,
    0xA8,
    0x3A,
    0x01,
    0x05,
    0x59,
    0x2A,
    0x46,
]


class Skipjack(BitGraphPrimitive):
    """
        Build the 32-round SKIPJACK block primitive graph.

        This implementation follows the NIST specification with an 80-bit key,
        64-bit block and 32 rounds (Rule A / Rule B schedule).

        Test vectors reference:
        - [NIST1998] SKIPJACK and KEA Algorithm Specifications, Annex III
            https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/skipjack/skipjack.pdf

    EXAMPLES::

        >>> primitive = Skipjack()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xaaae8ede6764143d', 64)
    """

    def __init__(self, number_of_rounds=32):
        self.WORD_SIZE = 16
        self.BLOCK_SIZE = 64
        self.KEY_SIZE = 80

        super().__init__(
            family_name="skipjack",
            primitive_type="block_cipher",
            primitive_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            primitive_inputs_bit_size=[self.BLOCK_SIZE, self.KEY_SIZE],
            primitive_output_bit_size=self.BLOCK_SIZE,
        )

        # Initialize state: w1, w2, w3, w4 from plaintext
        # Plaintext format (big-endian): bits 0-15 (w1), 16-31 (w2), 32-47 (w3), 48-63 (w4)
        w1, w2, w3, w4 = self._initialize_state()

        # 32 rounds
        for round_number in range(number_of_rounds):
            self._builder.add_round()
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
        w1 = BitState([INPUT_PLAINTEXT], [list(range(0, 16))])
        w2 = BitState([INPUT_PLAINTEXT], [list(range(16, 32))])
        w3 = BitState([INPUT_PLAINTEXT], [list(range(32, 48))])
        w4 = BitState([INPUT_PLAINTEXT], [list(range(48, 64))])
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
        # Extract g[0] (high byte) and g[1] (low byte)
        # Handle both layouts:
        # 1) Single-ID 16-bit word: id=[x], positions=[[0..15]]
        # 2) Multi-ID 2x8-bit word: id=[x_hi, x_lo], positions=[[0..7], [0..7]]
        if len(word.id) == 1:
            g0 = BitState(word.id, [word.input_bit_positions[0][0:8]])
            g1 = BitState(word.id, [word.input_bit_positions[0][8:16]])
        else:
            g0 = BitState([word.id[0]], [word.input_bit_positions[0]])
            g1 = BitState([word.id[1]], [word.input_bit_positions[1]])

        g_prev = g0  # g[0]
        g_out = g1  # g[1]

        for feistel_round in range(4):
            # Key index: j = (4*step + feistel_round) % 10
            key_index = (4 * step + feistel_round) % 10

            # Extract corresponding key byte (KEY = 80 bits, 10 bytes in big-endian)
            # byte[0] = bits 0-7, ..., byte[9] = bits 72-79
            bit_start = key_index * 8
            bit_end = (key_index + 1) * 8
            key_byte = BitState([INPUT_KEY], [list(range(bit_start, bit_end))])

            # XOR: g_out XOR key_byte
            self.add_xor_component(
                [g_out.id[0], key_byte.id[0]],
                [g_out.input_bit_positions[0], key_byte.input_bit_positions[0]],
                8,
            )
            xor_result = BitState([self.get_current_component_id()], [list(range(8))])

            # SBOX: F[xor_result]
            self.add_sbox_component(
                [xor_result.id[0]], [xor_result.input_bit_positions[0]], 8, SKIPJACK_FTABLE
            )
            sbox_result = BitState([self.get_current_component_id()], [list(range(8))])

            # XOR: sbox_result XOR g_prev
            self.add_xor_component(
                [sbox_result.id[0], g_prev.id[0]],
                [sbox_result.input_bit_positions[0], g_prev.input_bit_positions[0]],
                8,
            )
            g_new = BitState([self.get_current_component_id()], [list(range(8))])

            # Update for next iteration
            g_prev = g_out
            g_out = g_new

        return BitState(
            [g_prev.id[0], g_out.id[0]],
            [g_prev.input_bit_positions[0], g_out.input_bit_positions[0]],
        )

    def _rule_a(self, w1, w2, w3, w4, counter, round_number):
        """Rule A: w1' = G(w1) XOR w4 XOR counter, w2' = G(w1), w3' = w2, w4' = w3"""
        g_output = self._g_permutation(w1, round_number)

        # Counter
        self.add_constant_component(16, counter)
        counter_comp = BitState([self.get_current_component_id()], [list(range(16))])

        # Both g_output and w4 can be multi-ID (2x8-bit), so flatten both.
        self.add_xor_component(
            g_output.id + w4.id + [counter_comp.id[0]],
            g_output.input_bit_positions
            + w4.input_bit_positions
            + [counter_comp.input_bit_positions[0]],
            16,
        )
        w1_new = BitState([self.get_current_component_id()], [list(range(16))])

        return w1_new, g_output, w2, w3

    def _rule_b(self, w1, w2, w3, w4, counter, round_number):
        """Rule B: w1' = w4, w2' = G(w1), w3' = w1 XOR w2 XOR counter, w4' = w3"""
        g_output = self._g_permutation(w1, round_number)

        # Counter
        self.add_constant_component(16, counter)
        counter_comp = BitState([self.get_current_component_id()], [list(range(16))])

        # w1 and w2 can be multi-ID, so flatten both for a full 16-bit XOR each.
        self.add_xor_component(w1.id + w2.id, w1.input_bit_positions + w2.input_bit_positions, 16)
        temp = BitState([self.get_current_component_id()], [list(range(16))])

        self.add_xor_component(
            [temp.id[0], counter_comp.id[0]],
            [temp.input_bit_positions[0], counter_comp.input_bit_positions[0]],
            16,
        )
        w3_new = BitState([self.get_current_component_id()], [list(range(16))])

        return w4, g_output, w3_new, w3

    def _add_round_output(self, w1, w2, w3, w4, round_number, total_rounds):
        """Add round output: wire w1||w2||w3||w4 directly, flattening multi-ID states."""
        input_links = []
        input_positions = []
        for w in [w1, w2, w3, w4]:
            input_links.extend(w.id)
            input_positions.extend(w.input_bit_positions)

        if round_number == total_rounds - 1:
            self.add_primitive_output_component(input_links, input_positions, 64)
        else:
            self.add_round_output_component(input_links, input_positions, 64)
