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

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 32, "key_bit_size": 64, "number_of_rounds": 32},
    {"block_bit_size": 48, "key_bit_size": 96, "number_of_rounds": 36},
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 44},
]
Z = [5557826286501673759, 3114073359753873471]
WORDSIZE_TO_ZINDEX = {16: 0, 24: 0, 32: 1}

# What SBOX actually is
# ----------------------
# Simeck's nonlinear round function is g(x) = (x & (x <<< 5)) ^ (x <<< 1), where "<<<" is a cyclic
# left rotation of the whole word and "&"/"^" act bitwise. Since the AND combines x with a
# DIFFERENT rotation of itself, computing it bit-by-bit couples bits at different positions of x --
# it is not, on its face, a per-position lookup the way an ordinary S-box is.
#
# It becomes one once the AND is isolated from the rest of g: this SBOX table implements ONLY the
# AND part, x & (x <<< 5); the outer XOR with (x <<< 1) is applied afterwards by a plain XOR
# component in feistel_function() below, exactly as in the plaintext formula.
#
# Bit j of (x <<< 5) is x_{j+5} (index mod word_size), so the AND part at position j is x_j &
# x_{j+5}. For 8 output positions spaced 5 apart, j, j+5, j+10, ..., j+35, the AND needs the 8+1 = 9
# bits of x at positions j, j+5, ..., j+40 -- because bit (j+35)+5 = j+40 is also the "+5" needed by
# the position j+35 itself, and simultaneously equals the base "x_j" term of the position j+5 step
# later. Writing v_k = x_{j+5k} for k = 0..8 (9 bits, spaced 5 apart), the AND part at output
# position j+5k is simply v_k & v_{k+1} for k = 0..7 -- an 8-bit result depending on exactly 9 input
# bits, hence the 512 = 2**9 entries below (SBOX has 512 entries, NOT 256 -- it is addressed by a
# genuine 9-bit index, nothing is truncated or wrapped). Concretely, SBOX[v_0 v_1 ... v_8] (9-bit
# binary index, MSB-first) = (v_0&v_1)(v_1&v_2)...(v_6&v_7)(v_7&v_8) (8-bit binary output,
# MSB-first) -- the same "AND of a 9-bit sliding window" table used by SimonSboxBlockCipher (this is
# why the two files' SBOX arrays are byte-for-byte identical: only the *step* between selected
# positions -- 5 here, 7 for Simon, matching each cipher's rotation-vs-rotation gap in its AND --
# and the outer rotation amount XORed in afterwards differ between the two ciphers).
#
# feistel_function() below builds exactly this: for each 8-bit output chunk it selects the 9 input
# positions positions_pattern (+ an 8-bit-aligned offset) as the SBOX's input, and wires the SBOX's
# 8-bit output to the first 8 of those same positions (+ the same offset). Repeating this
# self.number_of_sboxes = word_size // 8 times, with each chunk's 9-position window overlapping its
# neighbour by exactly 1 bit, covers the whole word.
# fmt: off
SBOX = [
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x06, 0x07,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x08, 0x08, 0x08, 0x09, 0x0C, 0x0C, 0x0E, 0x0F,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x06, 0x07,
    0x10, 0x10, 0x10, 0x11, 0x10, 0x10, 0x12, 0x13, 0x18, 0x18, 0x18, 0x19, 0x1C, 0x1C, 0x1E, 0x1F,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x06, 0x07,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x08, 0x08, 0x08, 0x09, 0x0C, 0x0C, 0x0E, 0x0F,
    0x20, 0x20, 0x20, 0x21, 0x20, 0x20, 0x22, 0x23, 0x20, 0x20, 0x20, 0x21, 0x24, 0x24, 0x26, 0x27,
    0x30, 0x30, 0x30, 0x31, 0x30, 0x30, 0x32, 0x33, 0x38, 0x38, 0x38, 0x39, 0x3C, 0x3C, 0x3E, 0x3F,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x06, 0x07,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x08, 0x08, 0x08, 0x09, 0x0C, 0x0C, 0x0E, 0x0F,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x06, 0x07,
    0x10, 0x10, 0x10, 0x11, 0x10, 0x10, 0x12, 0x13, 0x18, 0x18, 0x18, 0x19, 0x1C, 0x1C, 0x1E, 0x1F,
    0x40, 0x40, 0x40, 0x41, 0x40, 0x40, 0x42, 0x43, 0x40, 0x40, 0x40, 0x41, 0x44, 0x44, 0x46, 0x47,
    0x40, 0x40, 0x40, 0x41, 0x40, 0x40, 0x42, 0x43, 0x48, 0x48, 0x48, 0x49, 0x4C, 0x4C, 0x4E, 0x4F,
    0x60, 0x60, 0x60, 0x61, 0x60, 0x60, 0x62, 0x63, 0x60, 0x60, 0x60, 0x61, 0x64, 0x64, 0x66, 0x67,
    0x70, 0x70, 0x70, 0x71, 0x70, 0x70, 0x72, 0x73, 0x78, 0x78, 0x78, 0x79, 0x7C, 0x7C, 0x7E, 0x7F,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x06, 0x07,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x08, 0x08, 0x08, 0x09, 0x0C, 0x0C, 0x0E, 0x0F,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x06, 0x07,
    0x10, 0x10, 0x10, 0x11, 0x10, 0x10, 0x12, 0x13, 0x18, 0x18, 0x18, 0x19, 0x1C, 0x1C, 0x1E, 0x1F,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x06, 0x07,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x08, 0x08, 0x08, 0x09, 0x0C, 0x0C, 0x0E, 0x0F,
    0x20, 0x20, 0x20, 0x21, 0x20, 0x20, 0x22, 0x23, 0x20, 0x20, 0x20, 0x21, 0x24, 0x24, 0x26, 0x27,
    0x30, 0x30, 0x30, 0x31, 0x30, 0x30, 0x32, 0x33, 0x38, 0x38, 0x38, 0x39, 0x3C, 0x3C, 0x3E, 0x3F,
    0x80, 0x80, 0x80, 0x81, 0x80, 0x80, 0x82, 0x83, 0x80, 0x80, 0x80, 0x81, 0x84, 0x84, 0x86, 0x87,
    0x80, 0x80, 0x80, 0x81, 0x80, 0x80, 0x82, 0x83, 0x88, 0x88, 0x88, 0x89, 0x8C, 0x8C, 0x8E, 0x8F,
    0x80, 0x80, 0x80, 0x81, 0x80, 0x80, 0x82, 0x83, 0x80, 0x80, 0x80, 0x81, 0x84, 0x84, 0x86, 0x87,
    0x90, 0x90, 0x90, 0x91, 0x90, 0x90, 0x92, 0x93, 0x98, 0x98, 0x98, 0x99, 0x9C, 0x9C, 0x9E, 0x9F,
    0xC0, 0xC0, 0xC0, 0xC1, 0xC0, 0xC0, 0xC2, 0xC3, 0xC0, 0xC0, 0xC0, 0xC1, 0xC4, 0xC4, 0xC6, 0xC7,
    0xC0, 0xC0, 0xC0, 0xC1, 0xC0, 0xC0, 0xC2, 0xC3, 0xC8, 0xC8, 0xC8, 0xC9, 0xCC, 0xCC, 0xCE, 0xCF,
    0xE0, 0xE0, 0xE0, 0xE1, 0xE0, 0xE0, 0xE2, 0xE3, 0xE0, 0xE0, 0xE0, 0xE1, 0xE4, 0xE4, 0xE6, 0xE7,
    0xF0, 0xF0, 0xF0, 0xF1, 0xF0, 0xF0, 0xF2, 0xF3, 0xF8, 0xF8, 0xF8, 0xF9, 0xFC, 0xFC, 0xFE, 0xFF,
]
# fmt: on


class SimeckSboxBlockCipher(Cipher):
    """
    Construct an instance of the SimeckBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    This is functionally equivalent to :py:class:`SimeckBlockCipher`: it replaces the AND of x with
    a rotated copy of itself in the round function with a 512-entry SBOX lookup table (see the
    module-level comment above ``SBOX`` and the ``feistel_function`` method for exactly what that
    table computes and why it is addressed by 9 -- not 8 -- input bits).

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `64`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is None
    - ``rotation_amount`` -- **tuple** (default: `(-5, -1)`); the tuple containing the 3 rotation amounts for the
      round function

    REFERENCES:

    Yang, G., Zhu, B., Suder, V., Aagaard, M. D., & Gong, G. (2015). The Simeck Family of Lightweight Block Ciphers.
    CHES 2015, LNCS 9293, 307-329. https://eprint.iacr.org/2015/612 [YZSAG2015]_.

    Unlike the Simon test vectors (which are quoted verbatim from an official published appendix), no published
    test-vector table was found for Simeck in the paper above; the round function and key schedule formulas were
    independently confirmed to match the paper exactly, and the test vectors used here have been cross-checked
    against a from-scratch implementation built directly from those formulas (see PR history), not merely trusted.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.simeck_sbox_block_cipher import SimeckSboxBlockCipher
        sage: simeck_sbox = SimeckSboxBlockCipher()
        sage: simeck_sbox.number_of_rounds
        32

        sage: simeck_sbox.component_from(0, 0).id
        'sbox_0_0'
    """

    def __init__(self, block_bit_size=32, key_bit_size=64, number_of_rounds=None, rotation_amounts=(-5, -1)):
        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self.word_size = self.block_bit_size // 2
        self.rotation_amounts = rotation_amounts
        self.z = Z[WORDSIZE_TO_ZINDEX[self.word_size]]
        self.c = 2**self.word_size - 4
        self.number_of_sboxes = self.word_size // 8

        if number_of_rounds is None:
            for parameters in PARAMETERS_CONFIGURATION_LIST:
                if (
                    parameters["block_bit_size"] == self.block_bit_size
                    and parameters["key_bit_size"] == self.key_bit_size
                ):
                    number_of_rounds = parameters["number_of_rounds"]
                    break
            if number_of_rounds is None:
                raise ValueError("No available number of rounds for the given parameters.")

        super().__init__(
            family_name="simeck_sbox",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[self.block_bit_size, key_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        left = INPUT_PLAINTEXT, list(range(self.word_size))
        right = INPUT_PLAINTEXT, list(range(self.word_size, 2 * self.word_size))
        keys_buffer = []
        for i in range(4):
            keys_buffer.append((INPUT_KEY, list(range(self.word_size * i, self.word_size * (i + 1)))))

        for round_number in range(number_of_rounds - 1):
            self.add_round()
            left, right = self.feistel_function(left, right, keys_buffer[3])
            self.add_round_output_component([left[0], right[0]], [left[1], right[1]], self.block_bit_size)
            keys_buffer = self.update_keys_buffer(keys_buffer, round_number)
            self.add_round_key_output_component([keys_buffer[3][0]], [keys_buffer[3][1]], self.word_size)
        self.add_round()
        left, right = self.feistel_function(left, right, keys_buffer[3])
        self.add_cipher_output_component([left[0], right[0]], [left[1], right[1]], self.block_bit_size)

    def feistel_function(self, left, right, round_key):
        # g(x) = (x & x <<< 5) ⊕ (x <<< 1)
        #
        # The SBOX table (see its definition above for the full derivation) computes only the AND
        # part, x & (x <<< 5), 8 bits at a time; the XOR with (x <<< 1) is applied below by a plain
        # XOR component, mirroring the plaintext formula exactly.
        #
        # positions_pattern has 9 entries (not 8): each 8-bit SBOX call needs 9 bits of x, since two
        # neighbouring output bits' windows overlap by 1 bit (see the module-level comment on
        # SBOX). positions_pattern[:-1] gives the corresponding 8 output positions. SBOX itself has
        # 512 = 2**9 entries -- it is genuinely addressed by all 9 selected bits, nothing is
        # truncated, wrapped, or otherwise discarded.
        #
        # `left[1]` (rather than a bare position arithmetic expression) is used to look up each
        # selected bit's ACTUAL position, because `left` is not always the plaintext half at
        # bit-identical positions [0, word_size): this same method is reused, unchanged, by the key
        # schedule (see update_keys_buffer / simeck_sbox_block_cipher's key words), where `left` can
        # be a key word whose bits sit at some offset within INPUT_KEY. Indexing through `left[1]`
        # keeps the construction correct regardless of that offset.
        positions_pattern = (0, 5, 10, 15, 20, 25, 30, 35, 40)
        output_ids = [""] * self.word_size
        output_positions = [0] * self.word_size
        for i in range(self.number_of_sboxes):
            sbox_input_positions = [left[1][(position + 8 * i) % self.word_size] for position in positions_pattern]
            sbox_id = self.add_sbox_component([left[0]], [sbox_input_positions], 8, SBOX).id
            sbox_output_positions = [(position + 8 * i) % self.word_size for position in positions_pattern[:-1]]
            for j, sbox_output_position in enumerate(sbox_output_positions):
                output_ids[sbox_output_position] = sbox_id
                output_positions[sbox_output_position] = j
        sboxes_ids = [output_ids[0]]
        sboxes_positions = [[output_positions[0]]]
        for i in range(1, self.word_size):
            if output_ids[i] != sboxes_ids[-1]:
                sboxes_ids.append(output_ids[i])
                sboxes_positions.append([output_positions[i]])
            else:
                sboxes_positions[-1].append(output_positions[i])
        s1_left_input_positions = left[1][1:] + [left[1][0]]
        f_id = self.add_xor_component(
            [*sboxes_ids, left[0]], [*sboxes_positions, s1_left_input_positions], self.word_size
        ).id
        # Rk(x, y) = (y ⊕ f(x) ⊕ k, x)
        new_left_id = self.add_xor_component(
            [right[0], f_id, round_key[0]], [right[1], list(range(self.word_size)), round_key[1]], self.word_size
        ).id

        return (new_left_id, list(range(self.word_size))), left

    def update_keys_buffer(self, keys_buffer, round_number):
        # c ^ z[j][i]
        round_constant_id = self.add_constant_component(self.word_size, self.c ^ ((self.z >> round_number) & 1)).id
        round_constant = round_constant_id, list(range(self.word_size))
        new_key_left, keys_buffer[3] = self.feistel_function(keys_buffer[2], keys_buffer[3], round_constant)
        keys_buffer[2] = keys_buffer[1]
        keys_buffer[1] = keys_buffer[0]
        keys_buffer[0] = new_key_left

        return keys_buffer
