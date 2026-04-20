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
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 32, "key_bit_size": 80, "number_of_rounds": 254},
    {"block_bit_size": 48, "key_bit_size": 80, "number_of_rounds": 254},
    {"block_bit_size": 64, "key_bit_size": 80, "number_of_rounds": 254},
]

CONFIGURATION = {
    32: {"len_l1": 13, "len_l2": 19, "x": (12, 7, 8, 5, 3), "y": (18, 7, 12, 10, 8, 3), "steps": 1},
    48: {"len_l1": 19, "len_l2": 29, "x": (18, 12, 15, 7, 6), "y": (28, 19, 21, 13, 15, 6), "steps": 2},
    64: {"len_l1": 25, "len_l2": 39, "x": (24, 15, 20, 11, 9), "y": (38, 25, 33, 21, 14, 9), "steps": 3},
}

IR = (
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0,
    1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0,
    0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
)


class KatanBlockCipher(Cipher):
    """
    Construct an instance of the KatanBlockCipher class.

    Reference:
    - Python reference implementation: https://gist.github.com/raullenchai/2662701

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); the block size of the cipher. Valid values are `32`, `48`, and `64`.
    - ``key_bit_size`` -- **integer** (default: `80`); the key size of the cipher. KATAN uses a fixed 80-bit key.
    - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds. The default is `254`.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.katan_block_cipher import KatanBlockCipher
        sage: katan = KatanBlockCipher()
        sage: katan.number_of_rounds
        254

        sage: key = 0xFFFFFFFFFFFFFFFFFFFF
        sage: plaintext = 0x00000000
        sage: hex(katan.evaluate([plaintext, key]))
        '0x7e1ff945'

        sage: KatanBlockCipher(block_bit_size=48, number_of_rounds=4).id
        'katan_p48_k80_o48_r4'
    """

    def __init__(self, block_bit_size=32, key_bit_size=80, number_of_rounds=None):
        if block_bit_size not in CONFIGURATION:
            raise ValueError("No available configuration for the given block size.")
        if key_bit_size != 80:
            raise ValueError("KATAN uses a fixed 80-bit key.")

        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size
        self._config = CONFIGURATION[block_bit_size]
        self._zero_bit = None
        self._one_bit = None

        if number_of_rounds is None:
            number_of_rounds = 254

        super().__init__(
            family_name="katan",
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

        for round_number in range(number_of_rounds):
            self.add_round()
            while len(key_bits) <= 2 * round_number + 1:
                key_bits.append(
                    self._xor_bits([
                        key_bits[-80],
                        key_bits[-61],
                        key_bits[-50],
                        key_bits[-13],
                    ])
                )

            for _ in range(self._config["steps"]):
                fa = self._round_function_a(l1, key_bits, round_number)
                fb = self._round_function_b(l2, key_bits, round_number)
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
        component_id = self.add_XOR_component(
            [bit.id[0] for bit in bits], [bit.input_bit_positions[0] for bit in bits], 1
        ).id
        return ComponentState([component_id], [[0]])

    def _and_bits(self, left, right):
        component_id = self.add_AND_component(
            [left.id[0], right.id[0]], [left.input_bit_positions[0], right.input_bit_positions[0]], 1
        ).id
        return ComponentState([component_id], [[0]])

    def _and_with_ir(self, bit, ir_bit):
        if ir_bit == 0:
            return self._constant_bit(0)
        return bit

    def _round_function_a(self, l1, key_bits, round_number):
        x1, x2, x3, x4, x5 = self._config["x"]
        return self._xor_bits([
            l1[x1],
            l1[x2],
            self._and_bits(l1[x3], l1[x4]),
            self._and_with_ir(l1[x5], IR[round_number]),
            key_bits[2 * round_number],
        ])

    def _round_function_b(self, l2, key_bits, round_number):
        y1, y2, y3, y4, y5, y6 = self._config["y"]
        return self._xor_bits([
            l2[y1],
            l2[y2],
            self._and_bits(l2[y3], l2[y4]),
            self._and_bits(l2[y5], l2[y6]),
            key_bits[2 * round_number + 1],
        ])

    def _add_state_output(self, output_function, state):
        ordered_state = list(reversed(state))
        output_function(
            [bit.id[0] for bit in ordered_state],
            [bit.input_bit_positions[0] for bit in ordered_state],
            self.block_bit_size,
        )
