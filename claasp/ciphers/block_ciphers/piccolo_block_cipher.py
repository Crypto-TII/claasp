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

from typing import List, Tuple

from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import get_inputs_parameter
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT


SBOX = [0xE, 0x4, 0xB, 0x2, 0x3, 0x8, 0x0, 0x9, 0x1, 0xA, 0x7, 0xF, 0x6, 0xC, 0x5, 0xD]

DIFFUSION_MATRIX = [[2, 3, 1, 1],
                    [1, 2, 3, 1],
                    [1, 1, 2, 3],
                    [3, 1, 1, 2]]

GF16_IRREDUCIBLE_POLY = 0x13

RP_PERMUTATION = [2, 7, 4, 1, 6, 3, 0, 5]

BASE32_80 = 0x0f1e2d3c
BASE32_128 = 0x6547a98b

PARAMETERS_CONFIGURATION_LIST = [
    {'key_bit_size': 80, 'number_of_rounds': 25},
    {'key_bit_size': 128, 'number_of_rounds': 31},
]


def _c5(i: int) -> int:
    """5-bit representation of i, used to build the round constants."""
    return i & 0x1F


def _generate_constants(num_rounds: int, base32: int) -> List[int]:
    constants = []
    for i in range(num_rounds):
        c0 = _c5(0)
        c_i1 = _c5(i + 1)
        const = (c_i1 << 27) | (c0 << 22) | (c_i1 << 17) | (0 << 15) | (c_i1 << 10) | (c0 << 5) | c_i1
        const = (const ^ base32) & 0xFFFFFFFF

        constants.append((const >> 16) & 0xFFFF)
        constants.append(const & 0xFFFF)
    return constants


def _piccolo128_key_selection_order(rounds: int) -> List[int]:
    kk = list(range(8))
    order = []
    for i in range(2 * rounds):
        if (i + 2) % 8 == 0:
            kk = [kk[2], kk[1], kk[6], kk[7], kk[0], kk[3], kk[4], kk[5]]
        order.append(kk[(i + 2) % 8])
    return order


class PiccoloBlockCipher(Cipher):
    """
    Construct an instance of the PiccoloBlockCipher class.

    Piccolo is a 64 bit block cipher which supports 80 bits or 128 bits keys.
    The default number of round is 25 for Piccolo-80 and 31 for Piccolo-128.

    REFERENCES:
    Implementation and test vectors from [SIHMAS2011]_.

    INPUT:

    - ``key_bit_size`` -- **integer** (default: `80`); key size in bits (80 or 128)
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is None

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.piccolo_block_cipher import PiccoloBlockCipher
        sage: piccolo = PiccoloBlockCipher()
        sage: piccolo.number_of_rounds
        25

        sage: piccolo128 = PiccoloBlockCipher(key_bit_size=128)
        sage: ct = piccolo128.evaluate([0x0123456789abcdef, 0x00112233445566778899aabbccddeeff])
        sage: hex(ct)
        '0x5ec42cea657b89ff'
    """

    def __init__(self, key_bit_size=80, number_of_rounds=None):
        self.block_bit_size = 64
        if key_bit_size not in (80, 128):
            raise ValueError('key_bit_size must be 80 or 128')
        self.key_bit_size = key_bit_size
        if number_of_rounds is None:
            number_of_rounds = 25 if key_bit_size == 80 else 31
        r = number_of_rounds

        super().__init__(family_name='piccolo',
                         cipher_type=BLOCK_CIPHER,
                         cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                         cipher_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        x0 = ComponentState([INPUT_PLAINTEXT], [list(range(0, 16))])
        x1 = ComponentState([INPUT_PLAINTEXT], [list(range(16, 32))])
        x2 = ComponentState([INPUT_PLAINTEXT], [list(range(32, 48))])
        x3 = ComponentState([INPUT_PLAINTEXT], [list(range(48, 64))])

        self.add_round()

        wk, rk = (self.schedule_80(r) if self.key_bit_size == 80 else self.schedule_128(r))

        x0 = self._xor([x0, wk[0]])
        x2 = self._xor([x2, wk[1]])

        for i in range(r):
            if i > 0:
                self.add_round()

            x1 = self._xor([x1, self._f_function(x0), rk[2 * i]])
            x3 = self._xor([x3, self._f_function(x2), rk[2 * i + 1]])

            if i < r - 1:
                x0, x1, x2, x3 = self._round_permutation(x0, x1, x2, x3)
                ids, bits = get_inputs_parameter([x0, x1, x2, x3])

                self.add_round_output_component(ids, bits, self.block_bit_size)

        x0 = self._xor([x0, wk[2]])
        x2 = self._xor([x2, wk[3]])

        ids, bits = get_inputs_parameter([x0, x1, x2, x3])

        self.add_cipher_output_component(ids, bits, self.block_bit_size)

    def schedule_80(self, r: int) -> Tuple[List[ComponentState], List[ComponentState]]:
        def word(i):
            return list(range(16 * i, 16 * i + 16))
        k = [ComponentState([INPUT_KEY], [word(i)]) for i in range(5)]
        key_left = [ComponentState(k[i].id, [k[i].input_bit_positions[0][0:8]]) for i in range(5)]
        key_right = [ComponentState(k[i].id, [k[i].input_bit_positions[0][8:16]]) for i in range(5)]

        wk_bits = [
            ComponentState([INPUT_KEY], [key_left[0].input_bit_positions[0] + key_right[1].input_bit_positions[0]]),
            ComponentState([INPUT_KEY], [key_left[1].input_bit_positions[0] + key_right[0].input_bit_positions[0]]),
            ComponentState([INPUT_KEY], [key_left[4].input_bit_positions[0] + key_right[3].input_bit_positions[0]]),
            ComponentState([INPUT_KEY], [key_left[3].input_bit_positions[0] + key_right[4].input_bit_positions[0]]),
        ]

        constants = _generate_constants(r, BASE32_80)

        rk_bits = []

        for i in range(r):
            m = i % 5
            a, b = (2, 3) if m in (0, 2) else (0, 1) if m in (1, 4) else (4, 4)

            const_a_id = self.add_constant_component(16, constants[2 * i]).id
            const_a = ComponentState([const_a_id], [list(range(16))])
            const_b_id = self.add_constant_component(16, constants[2 * i + 1]).id
            const_b = ComponentState([const_b_id], [list(range(16))])

            rk_bits.append(self._xor([k[a], const_a]))
            rk_bits.append(self._xor([k[b], const_b]))
        return wk_bits, rk_bits

    def schedule_128(self, r: int) -> Tuple[List[ComponentState], List[ComponentState]]:
        def word(i):
            return list(range(16 * i, 16 * i + 16))

        word_n = 8

        k = [ComponentState([INPUT_KEY], [word(i)]) for i in range(word_n)]
        key_left = [ComponentState(k[i].id, [k[i].input_bit_positions[0][0:8]]) for i in range(word_n)]
        key_right = [ComponentState(k[i].id, [k[i].input_bit_positions[0][8:16]]) for i in range(word_n)]

        wk = [
            ComponentState([INPUT_KEY], [key_left[0].input_bit_positions[0] + key_right[1].input_bit_positions[0]]),
            ComponentState([INPUT_KEY], [key_left[1].input_bit_positions[0] + key_right[0].input_bit_positions[0]]),
            ComponentState([INPUT_KEY], [key_left[4].input_bit_positions[0] + key_right[7].input_bit_positions[0]]),
            ComponentState([INPUT_KEY], [key_left[7].input_bit_positions[0] + key_right[4].input_bit_positions[0]]),
        ]

        constants = _generate_constants(r, BASE32_128)
        order = _piccolo128_key_selection_order(r)
        rk = []

        for i in range(2 * r):

            const_id = self.add_constant_component(16, constants[i]).id
            const = ComponentState([const_id], [list(range(16))])

            rk.append(self._xor([k[order[i]], const]))

        return wk, rk

    def _sbox_layer(self, state: ComponentState) -> ComponentState:
        ids, bits = get_inputs_parameter([state])

        out_ids, out_bits = [], []
        for n in range(4):
            self.add_sbox_component(ids, [bits[0][4 * n: 4 * n + 4]], 4, SBOX)
            out_ids.append(self.get_current_component_id())
            out_bits.append(list(range(4)))

        return ComponentState(out_ids, out_bits)

    def _diffusion_layer(self, state: ComponentState) -> ComponentState:
        ids, bits = get_inputs_parameter([state])
        self.add_mix_column_component(ids, bits, 16, [DIFFUSION_MATRIX, GF16_IRREDUCIBLE_POLY, 4])
        return ComponentState([self.get_current_component_id()], [list(range(16))])

    def _f_function(self, state: ComponentState) -> ComponentState:
        sbox1 = self._sbox_layer(state)
        diffusion = self._diffusion_layer(sbox1)
        return self._sbox_layer(diffusion)

    def _round_permutation(self, X0: ComponentState, X1: ComponentState, X2: ComponentState,
                           X3: ComponentState) -> Tuple[ComponentState, ComponentState, ComponentState, ComponentState]:
        ids, bits = get_inputs_parameter([X0, X1, X2, X3])

        perm_id = self.add_word_permutation_component(ids, bits, self.block_bit_size, RP_PERMUTATION, 8).id

        return (
            ComponentState([perm_id], [list(range(0, 16))]),
            ComponentState([perm_id], [list(range(16, 32))]),
            ComponentState([perm_id], [list(range(32, 48))]),
            ComponentState([perm_id], [list(range(48, 64))]),
        )

    def _xor(self, terms: List[ComponentState]) -> ComponentState:
        """XOR all the terms in the list and return the corresponding ComponentState object."""
        if len(terms) == 0:
            raise Exception('Empty terms list.')

        ids, bits = get_inputs_parameter(terms)
        size = sum(len(p) for p in terms[0].input_bit_positions)
        comp = self.add_xor_component(ids, bits, size)
        return ComponentState([comp.id], [list(range(size))])
