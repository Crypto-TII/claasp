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
from decimal import Decimal, localcontext

from claasp._catalogue_metadata import _entry
from claasp.graph.bit_builder import BitGraphPrimitive, BitState
from claasp.primitive_inputs import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [
    {"word_size": 32, "key_bit_size": 128, "number_of_rounds": 20},
    {"word_size": 32, "key_bit_size": 192, "number_of_rounds": 20},
    {"word_size": 32, "key_bit_size": 256, "number_of_rounds": 20},
]


def rc6_magic_constants(word_size):
    """
    Return the magic constants ``(P_w, Q_w)`` of RC5 and RC6, ``P_w = Odd((e - 2) 2^w)`` and
    ``Q_w = Odd((phi - 1) 2^w)``, where ``Odd(x)``, the odd integer nearest to ``x``, is ``floor(x) | 1``.

    EXAMPLES::

        >>> from claasp.primitives.block_ciphers.rc6 import rc6_magic_constants
        >>> [hex(c) for c in rc6_magic_constants(32)]
        ['0xb7e15163', '0x9e3779b9']
    """
    if not isinstance(word_size, int) or isinstance(word_size, bool) or word_size < 1:
        raise ValueError("word_size must be a positive integer")
    with localcontext() as context:
        context.prec = word_size + 32
        scale = Decimal(2) ** word_size
        e = Decimal(1).exp()
        phi = (1 + Decimal(5).sqrt()) / 2
        return int((e - 2) * scale) | 1, int((phi - 1) * scale) | 1


class RC6(BitGraphPrimitive):
    """RC6 primitive represented by a typed bit graph.

    The construction preserves the legacy round and key-schedule conventions.

    EXAMPLES::

        >>> from claasp.primitives import RC6
        >>> hex(RC6().evaluate(0x02132435465768798a9bacbdcedfe0f1, 0x0123456789abcdef0112233445566778))
        '0x524e192f4715c6231f51f6367ea43f18'
    """

    def __init__(self, word_size=32, key_bit_size=128, number_of_rounds=20):
        if word_size < 8 or word_size & (word_size - 1):
            raise ValueError("word_size must be a power of two that is at least 8")
        if key_bit_size % 8 or not 8 <= key_bit_size <= 2040:
            raise ValueError("key_bit_size must be 8b with 1 <= b <= 255")
        if number_of_rounds < 1:
            raise ValueError("number_of_rounds must be at least 1")

        super().__init__(
            family_name="rc6",
            primitive_type=BLOCK_CIPHER,
            primitive_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            primitive_inputs_bit_size=[4 * word_size, key_bit_size],
            primitive_output_bit_size=4 * word_size,
        )

        w, r, b = word_size, number_of_rounds, key_bit_size // 8
        lg_w = w.bit_length() - 1
        all_bits = list(range(w))  # CLAASP numbers the bits of a word from the most significant one
        low_bits = all_bits[-lg_w:]  # the lg w least significant bits, which give a rotation amount

        self._builder.add_round()
        S = self._key_schedule(w, r, b)

        # Encryption (Section 2.2 of the specification)
        A, B, C, D = self._bytes_to_words(INPUT_PLAINTEXT, 4 * w // 8, w)

        # B = B + S[0], D = D + S[1]
        self.add_modadd_component(B.id + [S[0]], B.input_bit_positions + [all_bits], w, 2**w)
        B = BitState([self.get_current_component_id()], [all_bits])
        self.add_modadd_component(D.id + [S[1]], D.input_bit_positions + [all_bits], w, 2**w)
        D = BitState([self.get_current_component_id()], [all_bits])

        for i in range(1, r + 1):
            if i > 1:
                self._builder.add_round()

            # t = (B * (2B + 1)) <<< lg w and u = (D * (2D + 1)) <<< lg w, where 2B + 1 is wired as the bits of B
            # shifted left by one followed by the constant bit 1 (B and D are always whole outputs of a component)
            one = self.add_constant_component(1, 1)
            self.add_modmul_component(
                B.id + B.id + [one.id], [all_bits, all_bits[1:], [0]], w, 2**w
            )
            t = self.add_rotate_component([self.get_current_component_id()], [all_bits], w, -lg_w)
            self.add_modmul_component(
                D.id + D.id + [one.id], [all_bits, all_bits[1:], [0]], w, 2**w
            )
            u = self.add_rotate_component([self.get_current_component_id()], [all_bits], w, -lg_w)

            # A = ((A xor t) <<< u) + S[2i]
            self.add_xor_component(A.id + [t.id], A.input_bit_positions + [all_bits], w)
            self.add_variable_rotate_component(
                [self.get_current_component_id(), u.id], [all_bits, low_bits], w, -1
            )
            self.add_modadd_component(
                [self.get_current_component_id(), S[2 * i]], [all_bits, all_bits], w, 2**w
            )
            A = BitState([self.get_current_component_id()], [all_bits])

            # C = ((C xor u) <<< t) + S[2i + 1]
            self.add_xor_component(C.id + [u.id], C.input_bit_positions + [all_bits], w)
            self.add_variable_rotate_component(
                [self.get_current_component_id(), t.id], [all_bits, low_bits], w, -1
            )
            self.add_modadd_component(
                [self.get_current_component_id(), S[2 * i + 1]], [all_bits, all_bits], w, 2**w
            )
            C = BitState([self.get_current_component_id()], [all_bits])

            # (A, B, C, D) = (B, C, D, A)
            A, B, C, D = B, C, D, A
            if i < r:
                state = self._words_to_bytes([A, B, C, D], w)
                self.add_round_output_component(state.id, state.input_bit_positions, 4 * w)

        # A = A + S[2r + 2], C = C + S[2r + 3]
        self.add_modadd_component(
            A.id + [S[2 * r + 2]], A.input_bit_positions + [all_bits], w, 2**w
        )
        A = BitState([self.get_current_component_id()], [all_bits])
        self.add_modadd_component(
            C.id + [S[2 * r + 3]], C.input_bit_positions + [all_bits], w, 2**w
        )
        C = BitState([self.get_current_component_id()], [all_bits])
        ciphertext = self._words_to_bytes([A, B, C, D], w)
        self.add_primitive_output_component(ciphertext.id, ciphertext.input_bit_positions, 4 * w)

    def _key_schedule(self, w, r, b):
        """
        Return the component ids of the round keys ``S[0], ..., S[2r + 3]`` (key schedule in the Appendix of the
        specification). In the first step ``A = B = 0``, so the additions of ``A`` and ``B`` are left out there.
        """
        lg_w = w.bit_length() - 1
        all_bits = list(range(w))
        L = self._bytes_to_words(INPUT_KEY, b, w)
        c = len(L)
        P, Q = rc6_magic_constants(w)

        # S[0] = P_w, S[i] = S[i - 1] + Q_w
        S = [self.add_constant_component(w, (P + i * Q) % 2**w).id for i in range(2 * r + 4)]

        A = B = None
        i = j = 0
        v = 3 * max(c, 2 * r + 4)
        for _ in range(v):
            # A = S[i] = (S[i] + A + B) <<< 3
            total = S[i]
            if A is not None:
                total = self.add_modadd_component([total, A], [all_bits, all_bits], w, 2**w).id
                total = self.add_modadd_component([total, B], [all_bits, all_bits], w, 2**w).id
            A = S[i] = self.add_rotate_component([total], [all_bits], w, -3).id

            # B = L[j] = (L[j] + A + B) <<< (A + B)
            a_plus_b = (
                A
                if B is None
                else self.add_modadd_component([A, B], [all_bits, all_bits], w, 2**w).id
            )
            self.add_modadd_component(
                L[j].id + [a_plus_b], L[j].input_bit_positions + [all_bits], w, 2**w
            )
            B = self.add_variable_rotate_component(
                [self.get_current_component_id(), a_plus_b], [all_bits, all_bits[-lg_w:]], w, -1
            ).id
            L[j] = BitState([B], [all_bits])

            i = (i + 1) % (2 * r + 4)
            j = (j + 1) % c
        return S

    def _bytes_to_words(self, input_name, number_of_bytes, w):
        """
        Load the bytes of the input into ``w``-bit words as the specification does: the bytes go in order into the
        words, each word gets its first byte as least significant byte, and the last word is padded with zero bytes.
        CLAASP numbers the input bits from the most significant one, so byte ``k`` is bits ``8k, ..., 8k + 7``.
        """
        bytes_per_word = w // 8
        words = []
        for first_byte in range(0, number_of_bytes, bytes_per_word):
            last_byte = min(first_byte + bytes_per_word, number_of_bytes) - 1
            positions = [
                bit for k in range(last_byte, first_byte - 1, -1) for bit in range(8 * k, 8 * k + 8)
            ]
            padding = w - len(positions)
            if padding:
                zero = self.add_constant_component(padding, 0)
                words.append(BitState([zero.id, input_name], [list(range(padding)), positions]))
            else:
                words.append(BitState([input_name], [positions]))
        return words

    def _words_to_bytes(self, words, w):
        """The words as a byte string, each word least significant byte first (the inverse of ``_bytes_to_words``)."""
        ids, positions = [], []
        for word in words:
            for m in range(w // 8):
                ids += word.id
                positions.append(list(range(w - 8 * (m + 1), w - 8 * m)))
        return BitState(ids, positions)


__catalogue__ = (_entry("primitive", RC6),)
