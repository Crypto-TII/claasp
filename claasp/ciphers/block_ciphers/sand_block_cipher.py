# Copyright 2026 Technology Innovation Institute
# SPDX-License-Identifier: GPL-3.0-or-later
"""SAND with explicit AND/XOR components and the original master-key schedule."""

from itertools import groupby
from operator import index

from claasp.cipher import Cipher
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 48},
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 54},
]
_PERMUTATIONS = {
    64: (7, 4, 1, 6, 3, 0, 5, 2),
    128: (14, 15, 8, 9, 2, 3, 12, 13, 6, 7, 0, 1, 10, 11, 4, 5),
}


class SandBlockCipher(Cipher):
    """Construct standard SAND-64/128 or SAND-128/128, optionally reduced.

    SAND is a Feistel AND-RX block cipher. Each round combines two nonlinear
    nibble functions, a bit permutation and a round key. The final branch swap
    is omitted, including for a reduced-round instance, as in the designers'
    reference implementation. The graph uses the external nibble bit ordering
    throughout; it does not expose the paper's transposed internal state as an
    alternative plaintext interface. Integers use the published hexadecimal
    plaintext, master-key and ciphertext conventions.

    REFERENCES:

    Chen et al., *SAND: an AND-RX Feistel lightweight block cipher supporting
    S-box-based security evaluations*, Designs, Codes and Cryptography 90,
    155--198 (2022), https://doi.org/10.1007/s10623-021-00970-9;
    https://eprint.iacr.org/2021/1560, Sections 2.1--2.2 and Appendices A--B.

    INPUT:

    - ``block_bit_size`` -- integer, 64 (default) or 128.
    - ``key_bit_size`` -- integer, 128; other key sizes are unsupported.
    - ``number_of_rounds`` -- positive integer up to the standard round count;
      None (default) selects 48 rounds for 64-bit blocks or 54 for 128-bit blocks.

    OUTPUT: a CLAASP cipher graph with ``plaintext`` then ``key`` inputs, the
    actual linear key schedule, per-round state/key outputs, and one ciphertext.
    Construction does not evaluate the cipher or invoke a solver.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.sand_block_cipher import SandBlockCipher
        sage: cipher = SandBlockCipher()
        sage: cipher.number_of_rounds
        48
        sage: plaintext = 0x0f1f2f3f4f5f6f7f
        sage: key = 0x0f1f2f3f4f5f6f7f8f9fafbfcfdfefff
        sage: hex(cipher.evaluate([plaintext, key]))
        '0x4de90f3b2b5e706b'
        sage: reduced = SandBlockCipher(block_bit_size=128, number_of_rounds=3)
        sage: reduced.inputs_bit_size
        [128, 128]
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=None):
        block, key, rounds = self._parameters(
            block_bit_size, key_bit_size, number_of_rounds
        )
        super().__init__(
            family_name="sand",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block, key],
            cipher_output_bit_size=block,
        )
        self.word_size = block // 2
        self._build_rounds(block, key, rounds)

    @staticmethod
    def _parameters(block_bit_size, key_bit_size, number_of_rounds):
        try:
            block = index(block_bit_size)
            key = index(key_bit_size)
        except TypeError as exc:
            raise ValueError("SAND block and key sizes must be integers") from exc
        if block not in _PERMUTATIONS or key != 128:
            raise ValueError("SAND supports 64- or 128-bit blocks and a 128-bit key")
        standard = 48 if block == 64 else 54
        try:
            rounds = standard if number_of_rounds is None else index(number_of_rounds)
        except TypeError as exc:
            raise ValueError("SAND round count must be an integer") from exc
        if isinstance(number_of_rounds, bool) or not 1 <= rounds <= standard:
            raise ValueError(f"SAND round count must lie between 1 and {standard}")
        return block, key, rounds

    def _build_rounds(self, block, key, rounds):
        width = self.word_size
        left = [(INPUT_PLAINTEXT, i) for i in range(width)]
        right = [(INPUT_PLAINTEXT, i) for i in range(width, block)]
        words = key // width
        keys = [
            [(INPUT_KEY, i) for i in range(key - (j + 1) * width, key - j * width)]
            for j in range(words)
        ]
        for r in range(rounds):
            self.add_round()
            if r >= words:
                self._extend_keys(keys, r, words)
            ids, positions = self._links(keys[r])
            self.add_round_key_output_component(ids, positions, width)
            left, right = (
                self._xor(self._round_function(left, block), right, keys[r]),
                left,
            )
            state = right + left if r == rounds - 1 else left + right
            ids, positions = self._links(state)
            if r == rounds - 1:
                self.add_cipher_output_component(ids, positions, block)
            else:
                self.add_round_output_component(ids, positions, block)

    def _extend_keys(self, keys, r, words):
        transformed = keys[-1]
        for _ in range(3):
            transformed = self._key_step(transformed)
        constant = self.add_constant_component(self.word_size, r - words + 1)
        keys.append(self._xor(transformed, keys[r - words], self._bits(constant)))

    def _round_function(self, left, block):
        mixed = self._xor(self._g0(left), self._g1(left[4:] + left[:4]))
        width = self.word_size
        permuted = [None] * width
        for j, target in enumerate(_PERMUTATIONS[block]):
            for bit in range(4):
                permuted[width - 1 - (4 * target + bit)] = mixed[
                    width - 1 - (4 * j + bit)
                ]
        return permuted

    @staticmethod
    def _bits(component):
        return [(component.id, i) for i in range(component.output_bit_size)]

    @staticmethod
    def _links(bits):
        groups = [
            (name, [bit for _, bit in group])
            for name, group in groupby(bits, key=lambda item: item[0])
        ]
        return [name for name, _ in groups], [positions for _, positions in groups]

    def _xor(self, *operands):
        ids, positions = self._links([bit for operand in operands for bit in operand])
        return self._bits(self.add_xor_component(ids, positions, len(operands[0])))

    def _and(self, a, b):
        ids, positions = self._links(a + b)
        return self._bits(self.add_and_component(ids, positions, len(a)))

    @staticmethod
    def _interleave(words):
        return [bit for column in zip(*words) for bit in column]

    def _g0(self, value):
        x3, x2, x1, x0 = [value[i::4] for i in range(4)]
        y0 = self._xor(self._and(x3, x2), x0)
        y3 = self._xor(self._and(y0, x1), x3)
        return self._interleave([y3, x2, x1, y0])

    def _g1(self, value):
        x3, x2, x1, x0 = [value[i::4] for i in range(4)]
        y2 = self._xor(self._and(x3, x1), x2)
        y1 = self._xor(self._and(y2, x0), x1)
        return self._interleave([x3, y2, y1, x0])

    def _key_step(self, value):
        # A_n: rotate the raw nibbles right, then apply the feedback polynomial.
        rotated = value[-4:] + value[:-4]
        t = rotated[4:8]
        high = self._xor(rotated[:4], t[1:] + t[:1])
        second_high = self._xor(rotated[4:5], t[3:4])
        return high + second_high + rotated[5:]
