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


from claasp.graph.bit_builder import BitGraphPrimitive, BitState, get_inputs_parameter
from claasp.primitive_inputs import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

SBOX = [0xE, 0x4, 0xB, 0x2, 0x3, 0x8, 0x0, 0x9, 0x1, 0xA, 0x7, 0xF, 0x6, 0xC, 0x5, 0xD]

DIFFUSION_MATRIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]

GF16_IRREDUCIBLE_POLY = 0x13

RP_PERMUTATION = [6, 3, 0, 5, 2, 7, 4, 1]

BASE32_80 = 0x0F1E2D3C
BASE32_128 = 0x6547A98B

PARAMETERS_CONFIGURATION_LIST = [
    {"key_bit_size": 80, "number_of_rounds": 25},
    {"key_bit_size": 128, "number_of_rounds": 31},
]


def _c5(i: int) -> int:
    """5-bit representation of i, used to build the round constants."""
    return i & 0x1F


def _generate_constants(num_rounds: int, base32: int) -> list[int]:
    constants = []
    for i in range(num_rounds):
        c0 = _c5(0)
        c_i1 = _c5(i + 1)
        const = (
            (c_i1 << 27) | (c0 << 22) | (c_i1 << 17) | (0 << 15) | (c_i1 << 10) | (c0 << 5) | c_i1
        )
        const = (const ^ base32) & 0xFFFFFFFF

        constants.append((const >> 16) & 0xFFFF)
        constants.append(const & 0xFFFF)
    return constants


def _piccolo128_key_selection_order(rounds: int) -> list[int]:
    kk = list(range(8))
    order = []
    for i in range(2 * rounds):
        if (i + 2) % 8 == 0:
            kk = [kk[2], kk[1], kk[6], kk[7], kk[0], kk[3], kk[4], kk[5]]
        order.append(kk[(i + 2) % 8])
    return order


class Piccolo(BitGraphPrimitive):
    """
    Construct an instance of the Piccolo class.

    Piccolo is a 64 bit block primitive which supports 80 bits or 128 bits keys.
    The default number of round is 25 for Piccolo-80 and 31 for Piccolo-128.

    REFERENCES:
    Implementation and test vectors from [SIHMAS2011]_.

    INPUT:

    - ``key_bit_size`` -- **integer** (default: `80`); key size in bits (80 or 128)
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds. The primitive uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is None

    EXAMPLES::

        >>> primitive = Piccolo()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xf696a1a3f069bdae', 64)
    """

    def __init__(self, key_bit_size=80, number_of_rounds=None):
        self.block_bit_size = 64
        if key_bit_size not in (80, 128):
            raise ValueError("key_bit_size must be 80 or 128")
        self.key_bit_size = key_bit_size
        if number_of_rounds is None:
            number_of_rounds = 25 if key_bit_size == 80 else 31
        r = number_of_rounds

        super().__init__(
            family_name="piccolo",
            primitive_type=BLOCK_CIPHER,
            primitive_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            primitive_inputs_bit_size=[self.block_bit_size, self.key_bit_size],
            primitive_output_bit_size=self.block_bit_size,
        )

        x0 = BitState([INPUT_PLAINTEXT], [list(range(0, 16))])
        x1 = BitState([INPUT_PLAINTEXT], [list(range(16, 32))])
        x2 = BitState([INPUT_PLAINTEXT], [list(range(32, 48))])
        x3 = BitState([INPUT_PLAINTEXT], [list(range(48, 64))])

        self.add_round()

        wk, rk = self.schedule_80(r) if self.key_bit_size == 80 else self.schedule_128(r)

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

        self.add_primitive_output_component(ids, bits, self.block_bit_size)

    def schedule_80(self, r: int) -> tuple[list[BitState], list[BitState]]:
        """Build the schedule 80 transition in this primitive's typed operation graph."""

        def word(i):
            return list(range(16 * i, 16 * i + 16))

        k = [BitState([INPUT_KEY], [word(i)]) for i in range(5)]
        key_left = [BitState(k[i].id, [k[i].input_bit_positions[0][0:8]]) for i in range(5)]
        key_right = [BitState(k[i].id, [k[i].input_bit_positions[0][8:16]]) for i in range(5)]

        wk_bits = [
            BitState(
                [INPUT_KEY],
                [key_left[0].input_bit_positions[0] + key_right[1].input_bit_positions[0]],
            ),
            BitState(
                [INPUT_KEY],
                [key_left[1].input_bit_positions[0] + key_right[0].input_bit_positions[0]],
            ),
            BitState(
                [INPUT_KEY],
                [key_left[4].input_bit_positions[0] + key_right[3].input_bit_positions[0]],
            ),
            BitState(
                [INPUT_KEY],
                [key_left[3].input_bit_positions[0] + key_right[4].input_bit_positions[0]],
            ),
        ]

        constants = _generate_constants(r, BASE32_80)

        rk_bits = []

        for i in range(r):
            m = i % 5

            if m in (0, 2):
                a, b = (2, 3)
            elif m in (1, 4):
                a, b = (0, 1)
            else:
                a, b = (4, 4)

            const_a_id = self.add_constant_component(16, constants[2 * i]).id
            const_a = BitState([const_a_id], [list(range(16))])
            const_b_id = self.add_constant_component(16, constants[2 * i + 1]).id
            const_b = BitState([const_b_id], [list(range(16))])

            rk_bits.append(self._xor([k[a], const_a]))
            rk_bits.append(self._xor([k[b], const_b]))
        return wk_bits, rk_bits

    def schedule_128(self, r: int) -> tuple[list[BitState], list[BitState]]:
        """Build the schedule 128 transition in this primitive's typed operation graph."""

        def word(i):
            return list(range(16 * i, 16 * i + 16))

        word_n = 8

        k = [BitState([INPUT_KEY], [word(i)]) for i in range(word_n)]
        key_left = [BitState(k[i].id, [k[i].input_bit_positions[0][0:8]]) for i in range(word_n)]
        key_right = [BitState(k[i].id, [k[i].input_bit_positions[0][8:16]]) for i in range(word_n)]

        wk = [
            BitState(
                [INPUT_KEY],
                [key_left[0].input_bit_positions[0] + key_right[1].input_bit_positions[0]],
            ),
            BitState(
                [INPUT_KEY],
                [key_left[1].input_bit_positions[0] + key_right[0].input_bit_positions[0]],
            ),
            BitState(
                [INPUT_KEY],
                [key_left[4].input_bit_positions[0] + key_right[7].input_bit_positions[0]],
            ),
            BitState(
                [INPUT_KEY],
                [key_left[7].input_bit_positions[0] + key_right[4].input_bit_positions[0]],
            ),
        ]

        constants = _generate_constants(r, BASE32_128)
        order = _piccolo128_key_selection_order(r)
        rk = []

        for i in range(2 * r):
            const_id = self.add_constant_component(16, constants[i]).id
            const = BitState([const_id], [list(range(16))])

            rk.append(self._xor([k[order[i]], const]))

        return wk, rk

    def _sbox_layer(self, state: BitState) -> BitState:
        ids, bits = get_inputs_parameter([state])

        out_ids, out_bits = [], []
        for n in range(4):
            self.add_sbox_component(ids, [bits[0][4 * n : 4 * n + 4]], 4, SBOX)
            out_ids.append(self.get_current_component_id())
            out_bits.append(list(range(4)))

        return BitState(out_ids, out_bits)

    def _diffusion_layer(self, state: BitState) -> BitState:
        ids, bits = get_inputs_parameter([state])
        self.add_mix_column_component(ids, bits, 16, [DIFFUSION_MATRIX, GF16_IRREDUCIBLE_POLY, 4])
        return BitState([self.get_current_component_id()], [list(range(16))])

    def _f_function(self, state: BitState) -> BitState:
        sbox1 = self._sbox_layer(state)
        diffusion = self._diffusion_layer(sbox1)
        return self._sbox_layer(diffusion)

    def _round_permutation(
        self, x0: BitState, x1: BitState, x2: BitState, x3: BitState
    ) -> tuple[BitState, BitState, BitState, BitState]:
        ids, bits = get_inputs_parameter([x0, x1, x2, x3])

        perm_id = self.add_word_permutation_component(
            ids, bits, self.block_bit_size, RP_PERMUTATION, 8
        ).id

        return (
            BitState([perm_id], [list(range(0, 16))]),
            BitState([perm_id], [list(range(16, 32))]),
            BitState([perm_id], [list(range(32, 48))]),
            BitState([perm_id], [list(range(48, 64))]),
        )

    def _xor(self, terms: list[BitState]) -> BitState:
        """XOR all the terms in the list and return the corresponding BitState object."""
        if len(terms) == 0:
            raise ValueError("Empty terms list.")

        ids, bits = get_inputs_parameter(terms)
        size = sum(len(p) for p in terms[0].input_bit_positions)
        comp = self.add_xor_component(ids, bits, size)
        return BitState([comp.id], [list(range(size))])
