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
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

# rotation offsets (r0, r1, r2, r3) of the G function, Table 3.2 of the NORX v3.0 specification (AJN2016)
WORD_SIZE_TO_ROTATIONS = {32: (8, 11, 16, 31), 64: (8, 19, 40, 63)}

# index quadruples of the column step and the diagonal step of F, Fig. 3.3/3.4 of the NORX v3.0 specification
COLUMN_STEP = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]]
DIAGONAL_STEP = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]]

PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 4, "word_size": 32}, {"number_of_rounds": 4, "word_size": 64}]


class NorxPermutation(Cipher):
    """
    Construct an instance of the NorxPermutation class.

    This class is used to store compact representations of a permutation, used to generate the corresponding cipher.
    It implements the core permutation F of the NORX authenticated encryption scheme [AJN2016]_,
    i.e. the ``l``-round ARX permutation that is iterated inside the NORX sponge/duplex mode, not the full AEAD
    scheme (padding, absorption, encryption, tag generation).

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `4`); number of rounds ``l`` of the permutation. The designers'
      recommended instances NORX32-4-1 and NORX64-4-1 both use ``l = 4``.
    - ``word_size`` -- **integer** (default: `32`); the size of a state word in bits. Must be `32` (NORX32) or `64`
      (NORX64); these are the only two word sizes defined by the NORX v3.0 specification.
    - ``rotations`` -- **list of integer** (default: `None`); the rotation offsets `(r0, r1, r2, r3)` of the G
      function. When `None`, the offsets are picked automatically from ``word_size`` following Table 3.2 of the
      specification: `(8, 11, 16, 31)` for `word_size = 32` and `(8, 19, 40, 63)` for `word_size = 64`.

    EXAMPLES::

        sage: from claasp.ciphers.permutations.norx_permutation import NorxPermutation
        sage: norx = NorxPermutation(number_of_rounds=4, word_size=32)
        sage: norx.number_of_rounds
        4
        sage: norx.family_name
        'norx'

    The specification suggests verifying an implementation of F by checking that applying two rounds of F to the
    state `(0, 1, ..., 15)` yields the NORX initialisation constants `(u0, ..., u15)` of Table 3.4::

        sage: state = int(''.join(format(i, '032b') for i in range(16)), 2)
        sage: norx2 = NorxPermutation(number_of_rounds=2, word_size=32)
        sage: u = [0x0454EDAB, 0xAC6851CC, 0xB707322F, 0xA0C7C90D, 0x99AB09AC, 0xA643466D, 0x21C22362, 0x1230C950,
        ....:      0xA3D8D930, 0x3FA8B72C, 0xED84EB49, 0xEDCA4787, 0x335463EB, 0xF994220B, 0xBE0BF5C9, 0xD7C49104]
        sage: expected = int(''.join(format(w, '032b') for w in u), 2)
        sage: norx2.evaluate([state]) == expected
        True
    """

    def __init__(self, number_of_rounds=4, word_size=32, rotations=None):
        if word_size not in WORD_SIZE_TO_ROTATIONS:
            raise ValueError("word_size must be 32 or 64")

        self.word_bit_size = word_size
        self.state_bit_size = 16 * self.word_bit_size
        self.rotations = rotations if rotations is not None else WORD_SIZE_TO_ROTATIONS[word_size]

        super().__init__(
            family_name="norx",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        state = [
            ComponentState([INPUT_PLAINTEXT], [[k + i * self.word_bit_size for k in range(self.word_bit_size)]])
            for i in range(16)
        ]

        for round_number in range(number_of_rounds):
            self.add_round()
            state = self.round_function(state)

            inputs_id = []
            inputs_pos = []
            for word in state:
                inputs_id = inputs_id + word.id
                inputs_pos = inputs_pos + word.input_bit_positions

            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def round_function(self, state):
        for indexes in COLUMN_STEP:
            state = self.g_function(state, *indexes)
        for indexes in DIAGONAL_STEP:
            state = self.g_function(state, *indexes)

        return state

    def g_function(self, state, a_index, b_index, c_index, d_index):
        a, b, c, d = state[a_index], state[b_index], state[c_index], state[d_index]

        a = self.h_function(a, b)
        d = self.xor_then_rotate_right(d, a, self.rotations[0])
        c = self.h_function(c, d)
        b = self.xor_then_rotate_right(b, c, self.rotations[1])
        a = self.h_function(a, b)
        d = self.xor_then_rotate_right(d, a, self.rotations[2])
        c = self.h_function(c, d)
        b = self.xor_then_rotate_right(b, c, self.rotations[3])

        state[a_index], state[b_index], state[c_index], state[d_index] = a, b, c, d

        return state

    def h_function(self, x, y):
        # H(x, y) = (x xor y) xor ((x and y) << 1), the non-linear building block of the NORX G function
        self.add_and_component(x.id + y.id, x.input_bit_positions + y.input_bit_positions, self.word_bit_size)
        and_xy = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

        self.add_shift_component(and_xy.id, and_xy.input_bit_positions, self.word_bit_size, -1)
        shifted_and_xy = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

        self.add_xor_component(x.id + y.id, x.input_bit_positions + y.input_bit_positions, self.word_bit_size)
        xor_xy = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

        self.add_xor_component(
            xor_xy.id + shifted_and_xy.id,
            xor_xy.input_bit_positions + shifted_and_xy.input_bit_positions,
            self.word_bit_size,
        )

        return ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

    def xor_then_rotate_right(self, x, y, rotation_amount):
        self.add_xor_component(x.id + y.id, x.input_bit_positions + y.input_bit_positions, self.word_bit_size)
        xored = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

        self.add_rotate_component(xored.id, xored.input_bit_positions, self.word_bit_size, rotation_amount)

        return ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])
