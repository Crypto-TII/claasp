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

from claasp.DTOs.component_state import ComponentState
from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.katan_block_cipher import (
    CONFIGURATION,
    get_ir_bit,
    normalize_number_of_rounds,
)
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 32, "key_bit_size": 80, "number_of_rounds": 254},
    {"block_bit_size": 48, "key_bit_size": 80, "number_of_rounds": 254},
    {"block_bit_size": 64, "key_bit_size": 80, "number_of_rounds": 254},
]


class KtantanBlockCipher(Cipher):
    """
    Construct an instance of the KtantanBlockCipher class.

    Reference:
    - partially inspired by the C implementation in http://www.cs.technion.ac.il/~orrd/KATAN/katan.c

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); the block size of the cipher. Valid values are `32`, `48`, and `64`.
    - ``key_bit_size`` -- **integer** (default: `80`); the key size of the cipher. KTANTAN uses a fixed 80-bit key.
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds. The default is `254`.
    - ``ir_mode`` -- **string** (default: `"strict"`); how to handle rounds beyond the
        254-bit IR sequence. Use `"cycle"` to repeat the IR sequence.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.ktantan_block_cipher import KtantanBlockCipher
        sage: ktantan = KtantanBlockCipher()
        sage: ktantan.number_of_rounds
        254

        sage: key = 0xFFFFFFFFFFFFFFFFFFFF
        sage: plaintext = 0x00000000
        sage: hex(ktantan.evaluate([plaintext, key]))
        '0x22ea3988'

        sage: KtantanBlockCipher(block_bit_size=64, number_of_rounds=8).id
        'ktantan_p64_k80_o64_r8'

        sage: KtantanBlockCipher(number_of_rounds=255, ir_mode='cycle').number_of_rounds
        255
    """

    def __init__(self, block_bit_size=32, key_bit_size=80, number_of_rounds=None, ir_mode="strict"):
        if block_bit_size not in CONFIGURATION:
            raise ValueError("No available configuration for the given block size.")
        if key_bit_size != 80:
            raise ValueError("KTANTAN uses a fixed 80-bit key.")

        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self._config = CONFIGURATION[block_bit_size]
        self._zero_bit = None
        self._one_bit = None

        number_of_rounds = normalize_number_of_rounds(number_of_rounds)

        super().__init__(
            family_name="ktantan",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        l2 = [self._input_bit(INPUT_PLAINTEXT, self.block_bit_size - 1 - i) for i in range(self._config["len_l2"])]
        l1 = [
            self._input_bit(INPUT_PLAINTEXT, self.block_bit_size - 1 - (self._config["len_l2"] + i))
            for i in range(self._config["len_l1"])
        ]
        key_bits = [self._input_bit(INPUT_KEY, self.key_bit_size - 1 - i) for i in range(self.key_bit_size)]
        ka, kb = self._expand_round_keys(key_bits, number_of_rounds)

        for round_number in range(number_of_rounds):
            self.add_round()

            for _ in range(self._config["steps"]):
                fa = self._round_function_a(l1, ka, round_number, ir_mode)
                fb = self._round_function_b(l2, kb, round_number)
                l1 = [fb] + l1[:-1]
                l2 = [fa] + l2[:-1]

            if round_number != number_of_rounds - 1:
                self._add_state_output(self.add_round_output_component, l2 + l1)

        self._add_state_output(self.add_cipher_output_component, l2 + l1)

    @staticmethod
    def _input_bit(component_id, position):
        return ComponentState([component_id], [[position]])

    def _constant_bit(self, value):
        if value not in (0, 1):
            raise ValueError("Bit constants must be 0 or 1.")

        if value == 0 and self._zero_bit is None:
            self._zero_bit = ComponentState([self.add_constant_component(1, 0).id], [[0]])
        if value == 1 and self._one_bit is None:
            self._one_bit = ComponentState([self.add_constant_component(1, 1).id], [[0]])

        return self._zero_bit if value == 0 else self._one_bit

    def _xor_bits(self, bits):
        if len(bits) == 1:
            return bits[0]
        component_id = self.add_xor_component(
            [bit.id[0] for bit in bits], [bit.input_bit_positions[0] for bit in bits], 1
        ).id
        return ComponentState([component_id], [[0]])

    def _and_bits(self, left, right):
        component_id = self.add_and_component(
            [left.id[0], right.id[0]], [left.input_bit_positions[0], right.input_bit_positions[0]], 1
        ).id
        return ComponentState([component_id], [[0]])

    def _round_function_a(self, l1, ka, round_number, ir_mode):
        x1, x2, x3, x4, x5 = self._config["x"]
        return self._xor_bits([
            l1[x1],
            l1[x2],
            self._and_bits(l1[x3], l1[x4]),
            l1[x5] if get_ir_bit(round_number, ir_mode) else self._constant_bit(0),
            ka[round_number],
        ])

    def _round_function_b(self, l2, kb, round_number):
        y1, y2, y3, y4, y5, y6 = self._config["y"]
        return self._xor_bits([
            l2[y1],
            l2[y2],
            self._and_bits(l2[y3], l2[y4]),
            self._and_bits(l2[y5], l2[y6]),
            kb[round_number],
        ])

    def _add_state_output(self, output_function, state):
        ordered_state = list(reversed(state))
        output_function(
            [bit.id[0] for bit in ordered_state],
            [bit.input_bit_positions[0] for bit in ordered_state],
            self.block_bit_size,
        )

    @staticmethod
    def _mux4(values, s0, s1):
        return values[s0 + (s1 << 1)]

    @staticmethod
    def _mux16(values, s):
        return values[s[0] + (s[1] << 1) + (s[2] << 2) + (s[3] << 3)]

    def _expand_round_keys(self, key_bits, number_of_rounds):
        ka = []
        kb = []
        t = [1] * 8

        for _ in range(number_of_rounds):
            tmp = t[7] ^ t[6] ^ t[4] ^ t[2]
            t = [tmp] + t[:-1]

            s16 = [t[4], t[5], t[6], t[7]]
            a0 = self._mux16(key_bits[0:16], s16)
            a4 = self._mux16(key_bits[64:80], s16)

            x4f = [
                self._mux16(key_bits[16:32], s16),
                self._mux16(key_bits[32:48], s16),
                self._mux16(key_bits[48:64], s16),
                self._mux16(key_bits[64:80], s16),
            ]
            x4g = [
                self._mux16(key_bits[0:16], s16),
                self._mux16(key_bits[16:32], s16),
                self._mux16(key_bits[32:48], s16),
                self._mux16(key_bits[48:64], s16),
            ]

            ka.append(a0 if t[3] == 0 and t[2] == 0 else self._mux4(x4f, t[0], t[1]))
            kb.append(a4 if t[3] == 0 and t[2] == 1 else self._mux4(x4g, 1 - t[0], 1 - t[1]))

        return ka, kb
