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
from claasp.name_mappings import HASH_FUNCTION, INPUT_KEY, INPUT_MESSAGE


PARAMETERS_CONFIGURATION_LIST = [
    {
        'message_byte_size': 15,
        'compression_rounds': 2,
        'finalization_rounds': 4,
        'output_bit_size': 64,
    }
]


class SiphashMAC(Cipher):
    """
    Return a cipher object of SipHash.

    This implementation follows the reference description from Aumasson and
    Bernstein [AumassonBernstein2012]_ and the official reference implementation from the SipHash
    repository. The key is always 128-bit and the message size is fixed at
    construction time.

    INPUT:

    - ``message_byte_size`` -- **integer** (default: `15`); message size in bytes
    - ``compression_rounds`` -- **integer** (default: `2`); SipHash c rounds
    - ``finalization_rounds`` -- **integer** (default: `4`); SipHash d rounds
    - ``output_bit_size`` -- **integer** (default: `64`); digest size, either 64 or 128

    REFERENCES:

    Aumasson, J. P., & Bernstein, D. J. (2012). SipHash: a fast short-input PRF.
    https://cr.yp.to/siphash/siphash-20120918.pdf [AumassonBernstein2012]_.

    Additional reference implementations and test vectors are available at:
    https://github.com/veorq/SipHash and https://github.com/veorq/SipHash/blob/master/vectors.h

    EXAMPLES::

        sage: from claasp.ciphers.mac.siphash_mac import SiphashMAC
        sage: key = 0x000102030405060708090a0b0c0d0e0f

        sage: # Reference: vectors.h vectors_sip64[0]
        sage: siphash_empty = SiphashMAC(message_byte_size=0)
        sage: siphash_empty.evaluate([0, key]) == 0x726fdb47dd0e0e31
        True

        sage: # Reference: vectors.h vectors_sip64[7]
        sage: siphash_7 = SiphashMAC(message_byte_size=7)
        sage: message_7 = 0x00010203040506
        sage: siphash_7.evaluate([message_7, key]) == 0xab0200f58b01d137
        True

        sage: # Reference: vectors.h vectors_sip64[8]
        sage: siphash_8 = SiphashMAC(message_byte_size=8)
        sage: message_8 = 0x0001020304050607
        sage: siphash_8.evaluate([message_8, key]) == 0x93f5f5799a932462
        True

        sage: # Reference: siphash-20120918.pdf, page 19
        sage: # Also in vectors.h as vectors_sip64[15]
        sage: siphash = SiphashMAC(message_byte_size=15)
        sage: message = 0x000102030405060708090a0b0c0d0e
        sage: digest = 0xa129ca6149be45e5
        sage: siphash.evaluate([message, key]) == digest
        True

        sage: # Reference: vectors.h vectors_sip64[63]
        sage: siphash_63 = SiphashMAC(message_byte_size=63)
        sage: message_63 = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e
        sage: siphash_63.evaluate([message_63, key]) == 0x958a324ceb064572
        True

        sage: # Parametrization example: SipHash-1-3 with empty message
        sage: siphash_13 = SiphashMAC(message_byte_size=0, compression_rounds=1, finalization_rounds=3)
        sage: siphash_13.output_bit_size
        64

        sage: # Parametrization example: 128-bit output (SipHash-2-4-128)
        sage: # Reference: vectors.h vectors_sip128[15]
        sage: siphash_128 = SiphashMAC(message_byte_size=15, output_bit_size=128)
        sage: digest_128 = 0x11a8b03399e99354d9c3cf970fec087e
        sage: siphash_128.evaluate([message, key]) == digest_128
        True
    """

    def __init__(self, message_byte_size=15, compression_rounds=2, finalization_rounds=4, output_bit_size=64):
        self.word_size = 64
        self.message_byte_size = message_byte_size
        self.compression_rounds = compression_rounds
        self.finalization_rounds = finalization_rounds
        self.digest_bit_size = output_bit_size

        if self.message_byte_size < 0:
            raise ValueError('message_byte_size must be >= 0.')
        if self.compression_rounds < 0:
            raise ValueError('compression_rounds must be >= 0.')
        if self.finalization_rounds < 0:
            raise ValueError('finalization_rounds must be >= 0.')
        if self.digest_bit_size not in (64, 128):
            raise ValueError('output_bit_size must be either 64 or 128.')

        super().__init__(
            family_name='siphash',
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_MESSAGE, INPUT_KEY],
            cipher_inputs_bit_size=[max(8, self.message_byte_size * 8), 128],
            cipher_output_bit_size=self.digest_bit_size,
        )

        self.add_round()

        k0 = self._little_endian_64_from_input(INPUT_KEY, 0)
        k1 = self._little_endian_64_from_input(INPUT_KEY, 8)

        v0 = self._xor_words(k0, self._constant_word(0x736F6D6570736575))
        v1 = self._xor_words(k1, self._constant_word(0x646F72616E646F6D))
        v2 = self._xor_words(k0, self._constant_word(0x6C7967656E657261))
        v3 = self._xor_words(k1, self._constant_word(0x7465646279746573))

        if self.digest_bit_size == 128:
            v1 = self._xor_words(v1, self._constant_word(0xEE))

        message_words = self._message_words()
        final_word = self._message_final_word()

        for message_word in message_words:
            v3 = self._xor_words(v3, message_word)
            v0, v1, v2, v3 = self._apply_sip_rounds(v0, v1, v2, v3, self.compression_rounds)
            v0 = self._xor_words(v0, message_word)

        v3 = self._xor_words(v3, final_word)
        v0, v1, v2, v3 = self._apply_sip_rounds(v0, v1, v2, v3, self.compression_rounds)
        v0 = self._xor_words(v0, final_word)

        if self.digest_bit_size == 128:
            v2 = self._xor_words(v2, self._constant_word(0xEE))
        else:
            v2 = self._xor_words(v2, self._constant_word(0xFF))

        v0, v1, v2, v3 = self._apply_sip_rounds(v0, v1, v2, v3, self.finalization_rounds)
        digest_low = self._xor_four_words(v0, v1, v2, v3)

        if self.digest_bit_size == 64:
            self.add_cipher_output_component([digest_low.id], [digest_low.input_bit_positions[0]], 64)
        else:
            v1 = self._xor_words(v1, self._constant_word(0xDD))
            v0, v1, v2, v3 = self._apply_sip_rounds(v0, v1, v2, v3, self.finalization_rounds)
            digest_high = self._xor_four_words(v0, v1, v2, v3)
            self.add_cipher_output_component(
                [digest_low.id, digest_high.id],
                [digest_low.input_bit_positions[0], digest_high.input_bit_positions[0]],
                128,
            )

    def _apply_sip_rounds(self, v0, v1, v2, v3, number_of_rounds):
        for _ in range(number_of_rounds):
            self.add_round()
            v0, v1, v2, v3 = self._sip_round(v0, v1, v2, v3)

        return v0, v1, v2, v3

    def _byte_state_from_input(self, input_id, byte_index):
        return ComponentState(input_id, [list(range(byte_index * 8, (byte_index + 1) * 8))])

    def _constant_word(self, value, bit_size=64):
        component = self.add_constant_component(bit_size, value)
        return ComponentState(component.id, [list(range(bit_size))])

    def _little_endian_64_from_input(self, input_id, start_byte):
        ids = []
        bit_positions = []
        for i in range(7, -1, -1):
            byte_state = self._byte_state_from_input(input_id, start_byte + i)
            ids.append(byte_state.id)
            bit_positions.append(byte_state.input_bit_positions[0])
        return ComponentState(ids, bit_positions)

    def _message_final_word(self):
        full_words = self.message_byte_size // 8
        left = self.message_byte_size % 8
        if left == 0:
            return self._constant_word((self.message_byte_size & 0xFF) << 56)

        len_byte = self._constant_word(self.message_byte_size & 0xFF, bit_size=8)
        zero_byte = self._constant_word(0, bit_size=8)

        ids = [len_byte.id] + [zero_byte.id] * (7 - left)
        bit_positions = [len_byte.input_bit_positions[0]] + [zero_byte.input_bit_positions[0]] * (7 - left)

        for i in range(left - 1, -1, -1):
            byte_index = full_words * 8 + i
            byte_state = self._byte_state_from_input(INPUT_MESSAGE, byte_index)
            ids.append(byte_state.id)
            bit_positions.append(byte_state.input_bit_positions[0])
        return ComponentState(ids, bit_positions)

    def _message_words(self):
        words = []
        for word_index in range(self.message_byte_size // 8):
            words.append(self._little_endian_64_from_input(INPUT_MESSAGE, word_index * 8))

        return words

    def _modadd_words(self, word_a, word_b):
        links_a, pos_a = self._state_links_positions(word_a)
        links_b, pos_b = self._state_links_positions(word_b)
        component = self.add_modadd_component(
            links_a + links_b,
            pos_a + pos_b,
            64,
        )
        return ComponentState(component.id, [list(range(64))])

    def _rotate_left_word(self, word, amount):
        links, positions = self._state_links_positions(word)
        component = self.add_rotate_component(links, positions, 64, -amount)
        return ComponentState(component.id, [list(range(64))])

    def _sip_round(self, v0, v1, v2, v3):
        v0 = self._modadd_words(v0, v1)
        v1 = self._rotate_left_word(v1, 13)
        v1 = self._xor_words(v1, v0)
        v0 = self._rotate_left_word(v0, 32)
        v2 = self._modadd_words(v2, v3)
        v3 = self._rotate_left_word(v3, 16)
        v3 = self._xor_words(v3, v2)
        self._add_state_intermediate_output(v0, v1, v2, v3, "siphash_half_round")
        v0 = self._modadd_words(v0, v3)
        v3 = self._rotate_left_word(v3, 21)
        v3 = self._xor_words(v3, v0)
        v2 = self._modadd_words(v2, v1)
        v1 = self._rotate_left_word(v1, 17)
        v1 = self._xor_words(v1, v2)
        v2 = self._rotate_left_word(v2, 32)
        self._add_state_intermediate_output(v0, v1, v2, v3, "siphash_full_round")

        return v0, v1, v2, v3

    def _xor_four_words(self, word_a, word_b, word_c, word_d):
        xor_ab = self._xor_words(word_a, word_b)
        xor_cd = self._xor_words(word_c, word_d)

        return self._xor_words(xor_ab, xor_cd)

    def _xor_words(self, word_a, word_b):
        links_a, pos_a = self._state_links_positions(word_a)
        links_b, pos_b = self._state_links_positions(word_b)
        component = self.add_xor_component(
            links_a + links_b,
            pos_a + pos_b,
            64,
        )
        return ComponentState(component.id, [list(range(64))])

    def _state_links_positions(self, state):
        links = state.id if isinstance(state.id, list) else [state.id]
        positions = state.input_bit_positions
        return links, positions

    def _add_state_intermediate_output(self, v0, v1, v2, v3, output_tag):
        self.add_intermediate_output_component(
            [v0.id, v1.id, v2.id, v3.id],
            [v0.input_bit_positions[0], v1.input_bit_positions[0], v2.input_bit_positions[0], v3.input_bit_positions[0]],
            256,
            output_tag,
        )