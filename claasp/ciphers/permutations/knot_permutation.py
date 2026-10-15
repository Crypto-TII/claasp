# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
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
from claasp.utils.utils import get_inputs_parameter

NUMBER_OF_ROWS = 4

# The KNOT S-box S : F_2^4 -> F_2^4 (Sect. 2.3). The 4-bit input of a column is
# a_{3,j} || a_{2,j} || a_{1,j} || a_{0,j} with a_{3,j} the most significant bit.
# fmt: off
SBOX = [0x4, 0x0, 0xA, 0x7, 0xB, 0xE, 0x1, 0xD, 0x9, 0xF, 0x6, 0x8, 0x5, 0x2, 0xC, 0x3]
# fmt: on

# Per state width b: the ShiftRow left-rotation offsets (c_0, c_1, c_2, c_3) with
# c_0 = 0 (row 0 is never rotated) from Table 1, the default number of rounds
# (the initialization round number nr_0 of the matching KNOT-AEAD member) and the
# default degree d of the maximal-length LFSR generating CONST_d for AddRoundConstant.
KNOT_PARAMETERS = {
    256: {"shift_row_offsets": [0, 1, 8, 25], "number_of_rounds": 52, "lfsr_degree": 6},
    384: {"shift_row_offsets": [0, 1, 8, 55], "number_of_rounds": 76, "lfsr_degree": 7},
    512: {"shift_row_offsets": [0, 1, 16, 25], "number_of_rounds": 100, "lfsr_degree": 7},
}

# Feedback taps of the d-bit maximal-length LFSRs used by AddRoundConstant (Sect. 2.2):
# the new value of rc_0 is the XOR of the register bits at these positions.
LFSR_FEEDBACK_TAPS = {6: (5, 4), 7: (6, 5), 8: (7, 5, 4, 3)}

PARAMETERS_CONFIGURATION_LIST = [
    {"state_bit_size": 256, "number_of_rounds": 52},
    {"state_bit_size": 384, "number_of_rounds": 76},
    {"state_bit_size": 512, "number_of_rounds": 100},
]


def lfsr_next_state(register_value, lfsr_degree):
    """Return the next state of the ``lfsr_degree``-bit AddRoundConstant LFSR."""
    feedback = 0
    for tap in LFSR_FEEDBACK_TAPS[lfsr_degree]:
        feedback ^= (register_value >> tap) & 1
    return ((register_value << 1) | feedback) & ((1 << lfsr_degree) - 1)


class KnotPermutation(Cipher):
    """
    Construct an instance of the KnotPermutation class.

    This is the underlying SP-network permutation p_b of the KNOT family of authenticated
    encryption algorithms and hash functions, as defined in Section 2 of the KNOT
    specification [ZDY+2019]_. Each round applies ``AddRoundConstant``, ``SubColumn``
    and ``ShiftRow`` to the ``4 x (b / 4)`` bit state.

    The ``b``-bit input is the state ``W = w_{b-1} || ... || w_1 || w_0`` of the KNOT
    specification, read as a big-endian integer: the plaintext most significant bit
    (CLAASP position 0) is ``w_{b-1}`` and the least significant bit (CLAASP position
    ``b - 1``) is ``w_0``. Following Section 2.1, ``w_0 ... w_{b/4-1}`` are arranged in
    row 0, ``w_{b/4} ... w_{b/2-1}`` in row 1 and so on, so ``a_{i,j} = w_{i * (b / 4) + j}``
    and the row word ``A_{b,i} = a_{i,b/4-1} || ... || a_{i,0}`` carries ``a_{i,0}`` as its
    least significant bit.

    INPUT:

        - ``state_bit_size`` -- **integer** (default: `256`); the state width ``b``, one of `256`, `384` or `512`
        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds of the permutation. When `None`, the
          initialization round number of the matching KNOT-AEAD member is used (`52`, `76` and `100` respectively)
        - ``lfsr_degree`` -- **integer** (default: `None`); degree ``d`` of the AddRoundConstant LFSR, one of `6`, `7`
          or `8`. When `None`, it defaults to `6` for ``b = 256`` and `7` for ``b = 384`` and ``b = 512``
        - ``bit_slice`` -- **boolean** (default: `False`); how ``SubColumn`` is built. When `False` the per-column
          4-bit S-box (Section 2.3) is used; when `True` the equivalent bit-slice form (Section 3.1) is used, i.e.
          12 word-wise Boolean operations per round on the four ``b / 4`` bit rows, which is markedly cheaper to
          build and to evaluate

    EXAMPLES::

        sage: from claasp.ciphers.permutations.knot_permutation import KnotPermutation
        sage: knot = KnotPermutation(state_bit_size=256, number_of_rounds=52)
        sage: knot.number_of_rounds
        52

        sage: knot.id
        'knot_p256_o256_r52'

        sage: knot.component_from(0, 0).id
        'constant_0_0'
    """

    def __init__(self, state_bit_size=256, number_of_rounds=None, lfsr_degree=None, bit_slice=False):
        if state_bit_size not in KNOT_PARAMETERS:
            raise ValueError("state_bit_size must be one of 256, 384 or 512")

        parameters = KNOT_PARAMETERS[state_bit_size]
        if number_of_rounds is None:
            number_of_rounds = parameters["number_of_rounds"]
        if lfsr_degree is None:
            lfsr_degree = parameters["lfsr_degree"]
        if lfsr_degree not in LFSR_FEEDBACK_TAPS:
            raise ValueError("lfsr_degree must be one of 6, 7 or 8")

        self.state_bit_size = state_bit_size
        self.row_bit_size = state_bit_size // NUMBER_OF_ROWS
        self.shift_row_offsets = parameters["shift_row_offsets"]
        self.lfsr_degree = lfsr_degree
        self.bit_slice = bit_slice

        super().__init__(
            family_name="knot",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        # state initialization: a_{i,j} = w_{i * (b / 4) + j}, so w_k (integer weight 2 ** k) sits at
        # plaintext position b - 1 - k. Row i therefore occupies the plaintext block that starts at
        # position (NUMBER_OF_ROWS - 1 - i) * (b / 4), listed most significant bit first as
        # a_{i,b/4-1}, ..., a_{i,0}.
        state = []
        for row in range(NUMBER_OF_ROWS):
            block_start = (NUMBER_OF_ROWS - 1 - row) * self.row_bit_size
            positions = [block_start + column for column in range(self.row_bit_size)]
            state.append(ComponentState([INPUT_PLAINTEXT], [positions]))

        round_constant = 1
        for round_number in range(number_of_rounds):
            self.add_round()
            state = self.round_function(state, round_constant)
            round_constant = lfsr_next_state(round_constant, self.lfsr_degree)

            # the output word is A_{b,3} || A_{b,2} || A_{b,1} || A_{b,0} (row 3 is the most significant)
            output_rows = [state[NUMBER_OF_ROWS - 1 - row] for row in range(NUMBER_OF_ROWS)]
            inputs_id, inputs_pos = get_inputs_parameter(output_rows)
            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def round_function(self, state, round_constant):
        state = self.add_round_constant(state, round_constant)
        state = self.sub_column(state)
        state = self.shift_row(state)

        return state

    def add_round_constant(self, state, round_constant):
        # XOR the d-bit round constant onto the first d bits w_0 || ... || w_{d-1} of the state, that is
        # onto a_{0,0} || ... || a_{0,d-1}. In the row 0 word a_{0,j} has integer weight 2 ** j, so the
        # constant is simply the d-bit LFSR value placed in the low bits of the row word.
        row_bit_size = self.row_bit_size
        constant_value = round_constant & ((1 << self.lfsr_degree) - 1)
        self.add_constant_component(row_bit_size, constant_value)
        constant = ComponentState([self.get_current_component_id()], [list(range(row_bit_size))])

        inputs_id, inputs_pos = get_inputs_parameter([state[0], constant])
        self.add_xor_component(inputs_id, inputs_pos, row_bit_size)
        state[0] = ComponentState([self.get_current_component_id()], [list(range(row_bit_size))])

        return state

    def sub_column(self, state):
        if self.bit_slice:
            return self._sub_column_bit_slice(state)

        return self._sub_column_sbox(state)

    def _sub_column_sbox(self, state):
        # SubColumn (Sect. 2.3): apply the 4-bit S-box to every column of the state.
        row_bit_size = self.row_bit_size

        sbox_ids = []
        for column in range(row_bit_size):
            # S-box input Col(j) = a_{3,j} || a_{2,j} || a_{1,j} || a_{0,j} (a_{3,j} is the most significant bit)
            input_id_links = [self._row_component_id(state[row], column) for row in reversed(range(NUMBER_OF_ROWS))]
            input_bit_positions = [
                [self._row_bit_position(state[row], column)] for row in reversed(range(NUMBER_OF_ROWS))
            ]
            self.add_sbox_component(input_id_links, input_bit_positions, NUMBER_OF_ROWS, SBOX)
            sbox_ids.append(self.get_current_component_id())

        # S-box output S(Col(j)) = b_{3,j} || b_{2,j} || b_{1,j} || b_{0,j}, so b_{i,j} is output bit 3 - i
        new_state = []
        for row in range(NUMBER_OF_ROWS):
            new_state.append(ComponentState(list(sbox_ids), [[NUMBER_OF_ROWS - 1 - row]] * row_bit_size))

        return new_state

    def _sub_column_bit_slice(self, state):
        # Bit-slice SubColumn (Sect. 3.1): the per-column S-box equals these 12 word-wise operations on the
        # rows A_{b,0..3} = state, producing B_{b,0..3}. Temporary names follow the T_{b,i} of the
        # specification. Every operation is bitwise, so the row bit ordering is irrelevant.
        row_0, row_1, row_2, row_3 = state

        temp_1 = self._word_operation(self.add_not_component, [row_0])
        temp_2 = self._word_operation(self.add_and_component, [row_1, temp_1])
        temp_3 = self._word_operation(self.add_xor_component, [row_2, temp_2])
        out_3 = self._word_operation(self.add_xor_component, [row_3, temp_3])
        temp_5 = self._word_operation(self.add_or_component, [row_1, row_2])
        temp_6 = self._word_operation(self.add_xor_component, [row_3, temp_1])
        out_2 = self._word_operation(self.add_xor_component, [temp_5, temp_6])
        temp_8 = self._word_operation(self.add_xor_component, [row_1, row_3])
        temp_9 = self._word_operation(self.add_and_component, [temp_3, temp_6])
        out_0 = self._word_operation(self.add_xor_component, [temp_8, temp_9])
        temp_11 = self._word_operation(self.add_and_component, [out_2, temp_8])
        out_1 = self._word_operation(self.add_xor_component, [temp_3, temp_11])

        return [out_0, out_1, out_2, out_3]

    def _word_operation(self, add_component, operands):
        inputs_id, inputs_pos = get_inputs_parameter(operands)
        add_component(inputs_id, inputs_pos, self.row_bit_size)
        return ComponentState([self.get_current_component_id()], [list(range(self.row_bit_size))])

    @staticmethod
    def _row_component_id(row_state, column):
        if len(row_state.id) == 1:
            return row_state.id[0]

        return row_state.id[column]

    @staticmethod
    def _row_bit_position(row_state, column):
        if len(row_state.id) == 1:
            return row_state.input_bit_positions[0][column]

        return row_state.input_bit_positions[column][0]

    def shift_row(self, state):
        row_bit_size = self.row_bit_size
        for row in range(1, NUMBER_OF_ROWS):
            # ShiftRow left-rotates row i over c_i bits, moving a_{i,j} to a_{i,j+c_i}. The row word is
            # laid out a_{i,b/4-1}, ..., a_{i,0} from the most significant bit down, and add_rotate_component
            # indexes the word from its most significant bit, so this is a left (negative) rotation.
            offset = (-self.shift_row_offsets[row]) % row_bit_size
            self.add_rotate_component(state[row].id, state[row].input_bit_positions, row_bit_size, offset)
            state[row] = ComponentState([self.get_current_component_id()], [list(range(row_bit_size))])

        return state
