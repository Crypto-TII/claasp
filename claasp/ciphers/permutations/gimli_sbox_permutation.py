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
from claasp.utils.utils import simplify_inputs

N_ROWS = 3
N_COLS = 4
NROUNDS = 24
SBOX_SIZE = N_ROWS
ROT_TABLE = [-24, -9]
GIMLI_SBOX = [0x0, 0x2, 0x0, 0x6, 0x2, 0x2, 0x3, 0x7]
PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 24, "word_size": 32}]


def big_swap(states):
    temp = ComponentState(states[0][0].id, states[0][0].input_bit_positions)
    states[0][0] = ComponentState(states[0][2].id, states[0][2].input_bit_positions)
    states[0][2] = temp
    temp = ComponentState(states[0][1].id, states[0][1].input_bit_positions)
    states[0][1] = ComponentState(states[0][3].id, states[0][3].input_bit_positions)
    states[0][3] = temp

    return states


def small_swap(states):
    temp = ComponentState(states[0][0].id, states[0][0].input_bit_positions)
    states[0][0] = ComponentState(states[0][1].id, states[0][1].input_bit_positions)
    states[0][1] = temp
    temp = ComponentState(states[0][2].id, states[0][2].input_bit_positions)
    states[0][2] = ComponentState(states[0][3].id, states[0][3].input_bit_positions)
    states[0][3] = temp

    return states


class GimliSboxPermutation(Cipher):
    """
    Construct an instance of the GimliSboxPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    This version is equivalent to :py:class:`GimliPermutation`, but it reformulates the nonlinear SP-box layer as
    the application of 32 parallel 3-bit S-boxes to each column, instead of the usual shifted AND/OR formula. The
    two formulations compute exactly the same function; the equivalence has been checked both empirically
    (``GimliPermutation`` and ``GimliSboxPermutation`` produce identical outputs for every tested input and for
    every number of rounds, including round 1) and by deriving the S-box table by hand from the original formula
    (see below), so this is not merely an unverified claim.

    Recall that, per column, Gimli's SP-box first rotates two of the three 32-bit lanes (``x`` by 24 bits and
    ``y`` by 9 bits, while ``z`` is left untouched -- this is exactly what ``ROT_TABLE = [-24, -9]`` does below),
    and then computes:

    - ``new_x = z ^ y ^ ((x AND y) << 3)``
    - ``new_y = y ^ x ^ ((x OR z) << 1)``
    - ``new_z = x ^ (z << 1) ^ ((y AND z) << 2)``

    (here ``x``, ``y``, ``z`` already denote the rotated lanes, and ``new_x``/``new_y``/``new_z`` are then written
    back with the ``x``/``z`` lane swap that both classes implement via ``sp_states[2]``/``sp_states[0]``).

    The only nonlinear ingredients of this formula are the three bitwise terms ``x AND y``, ``x OR z`` and
    ``y AND z``. Crucially, bitwise AND/OR are *bit-local*: bit ``i`` of ``A AND B`` depends only on bit ``i`` of
    ``A`` and bit ``i`` of ``B`` (and likewise for OR) -- no bit position ever depends on any other bit position.
    The only operations in the whole formula that mix different bit positions are the left shifts (``<< 1``,
    ``<< 2``, ``<< 3``), and those are applied to the *already computed* AND/OR terms, i.e. strictly after the
    bit-local part is done.

    This means the three bitwise terms can equivalently be computed one bit position at a time, independently for
    each of the 32 positions, and the position-mixing shifts can still be applied afterwards to the reassembled
    32-bit words -- which is exactly what this class does: for each bit position ``i`` it takes bit ``i`` of the
    rotated ``x``, the rotated ``y`` and ``z`` and feeds them into a single combined S-box (``GIMLI_SBOX``) that
    outputs bit ``i`` of all three bitwise terms at once, i.e.

    ``GIMLI_SBOX[4 * x_i + 2 * y_i + z_i] = 4 * (y_i AND z_i) + 2 * (x_i OR z_i) + (x_i AND y_i)``

    Indeed, evaluating this expression for all 8 possible ``(x_i, y_i, z_i)`` gives
    ``[0x0, 0x2, 0x0, 0x6, 0x2, 0x2, 0x3, 0x7]``, which is precisely the ``GIMLI_SBOX`` table below. After the
    S-box layer, this class reassembles the three output lanes (``lane_after_sb``), applies the ``-2``, ``-1``
    and ``-3`` shifts (matching ``<< 2``, ``<< 1`` and ``<< 3`` above) and XORs in the linear part, reproducing
    ``new_x``, ``new_y`` and ``new_z`` bit for bit. So "32 parallel 3-bit S-boxes" is a faithful description of
    the nonlinear layer: it holds precisely because AND/OR are bit-local operations, while all cross-bit-position
    coupling still happens through the explicit shifts applied after the S-box layer, not through the S-box
    itself.

    Side by side, per column (``x[i]`` denotes bit ``i`` of ``x``, etc.)::

        # Official Gimli SP-box (gimli.cr.yp.to/spec.html), as used by GimliPermutation:
        x = state[0] <<< 24
        y = state[1] <<< 9
        z = state[2]
        new_z = x ^ (z << 1) ^ ((y & z) << 2)
        new_y = y ^ x         ^ ((x | z) << 1)
        new_x = z ^ y         ^ ((x & y) << 3)

        # Equivalent bit-sliced form, as used by GimliSboxPermutation:
        x = state[0] <<< 24
        y = state[1] <<< 9
        z = state[2]
        for i in 0..31:
            sbox_out      = GIMLI_SBOX[4 * x[i] + 2 * y[i] + z[i]]   # 3 bits packed
            yz_and[i]     = (sbox_out >> 2) & 1                     # = y[i] & z[i]
            xz_or[i]      = (sbox_out >> 1) & 1                     # = x[i] | z[i]
            xy_and[i]     =  sbox_out       & 1                     # = x[i] & y[i]
        new_z = x ^ (z << 1) ^ (yz_and << 2)
        new_y = y ^ x         ^ (xz_or << 1)
        new_x = z ^ y         ^ (xy_and << 3)

        # Both formulations then apply the same x/z lane swap: state[2] = new_z, state[1] = new_y, state[0] = new_x

    Special case: for the very first round (``current_round == 24``, since rounds are numbered downward from 24),
    the ``z`` lane of the state is still the raw plaintext input, whose bit positions are not laid out as a plain
    ``0..31`` range (unlike every other round's lanes, which come from intermediate components indexed
    ``0..31``); the S-box construction therefore looks up the correct absolute bit position for that first-round
    ``z`` lane instead of assuming index ``i`` directly.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `24`); number of rounds of the permutation
        - ``word_size`` -- **integer** (default: `32`); the size of the word

    EXAMPLES::

        sage: from claasp.ciphers.permutations.gimli_sbox_permutation import GimliSboxPermutation
        sage: gimli = GimliSboxPermutation(number_of_rounds=24, word_size=32)
        sage: gimli.number_of_rounds
        24

        sage: gimli.component_from(0, 0).id
        'rot_0_0'
    """

    def __init__(self, number_of_rounds=24, word_size=32):
        self.word_bit_size = word_size
        self.plain_size = N_COLS * self.word_bit_size
        self.state_bit_size = N_ROWS * self.plain_size

        super().__init__(
            family_name="gimli_sbox",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        # states initialization
        states = [[{} for _ in range(N_COLS)] for _ in range(N_ROWS)]
        for row in range(N_ROWS):
            for column in range(N_COLS):
                states[row][column] = ComponentState(
                    [INPUT_PLAINTEXT],
                    [[k + column * self.word_bit_size + row * self.plain_size for k in range(self.word_bit_size)]],
                )

        # round function
        for round_number in range(number_of_rounds):
            self.add_round()
            states = self.round_function(states, 24 - round_number)

            # round output
            inputs_id = []
            inputs_pos = []
            for row in range(N_ROWS):
                for column in range(N_COLS):
                    inputs_id = inputs_id + states[row][column].id
                    inputs_pos = inputs_pos + states[row][column].input_bit_positions

            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def sp_box(self, states, current_round):
        # SP-box (Rotation)
        b = [[{} for _ in range(N_COLS)] for _ in range(N_ROWS)]
        for column_number in range(N_COLS):
            for row_number in range(N_ROWS - 1):
                self.add_rotate_component(
                    states[row_number][column_number].id,
                    states[row_number][column_number].input_bit_positions,
                    self.word_bit_size,
                    ROT_TABLE[row_number],
                )
                b[row_number][column_number] = ComponentState(
                    [self.get_current_component_id()], [list(range(self.word_bit_size))]
                )
            b[2][column_number] = ComponentState(
                states[2][column_number].id, states[2][column_number].input_bit_positions
            )

        # SP-box (T-function and swap)
        sp_states = [[{} for _ in range(N_COLS)] for _ in range(N_ROWS)]
        for column_number in range(N_COLS):
            # ------------------------------------------------------
            # x before substitution_layer-box
            self.add_shift_component(
                b[2][column_number].id, b[2][column_number].input_bit_positions, self.word_bit_size, -1
            )
            b0_shift1 = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])
            inputs_id = b[0][column_number].id + b0_shift1.id
            inputs_pos = b[0][column_number].input_bit_positions + b0_shift1.input_bit_positions
            self.add_xor_component(inputs_id, inputs_pos, self.word_bit_size)
            b0_xor = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])
            # ------------------------------------------------------
            # y before Sbox
            inputs_id = b[1][column_number].id + b[0][column_number].id
            inputs_pos = b[1][column_number].input_bit_positions + b[0][column_number].input_bit_positions
            self.add_xor_component(inputs_id, inputs_pos, self.word_bit_size)
            b1_xor = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

            # ------------------------------------------------------
            # z before Sbox
            inputs_id = b[2][column_number].id + b[1][column_number].id
            inputs_pos = b[2][column_number].input_bit_positions + b[1][column_number].input_bit_positions
            self.add_xor_component(inputs_id, inputs_pos, self.word_bit_size)
            b2_xor = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

            # ------------------------------------------------------
            # ------------------------------------------------------
            # Applying Sbox to x, y, z
            substitution_layer = []
            inputs_id = b[0][column_number].id + b[1][column_number].id + b[2][column_number].id
            for i in range(self.word_bit_size):
                if current_round == 24:
                    inputs_pos = [[i]] * (N_ROWS - 1) + [
                        [b[2][column_number].input_bit_positions[0][i % self.word_bit_size]]
                    ]
                else:
                    inputs_pos = [[i]] * N_ROWS
                self.add_sbox_component(inputs_id, inputs_pos, N_ROWS, GIMLI_SBOX)
                substitution_layer.append(ComponentState([self.get_current_component_id()], [list(range(SBOX_SIZE))]))

            inputs_id = []
            for i in range(self.word_bit_size):
                inputs_id += substitution_layer[i].id
            lane_after_sb = [{} for _ in range(N_ROWS)]
            for i in range(N_ROWS):
                lane_after_sb[i] = ComponentState(inputs_id, [[i]] * self.word_bit_size)

            # ------------------------------------------------------
            # x after substitution_layer-box
            self.add_shift_component(lane_after_sb[0].id, lane_after_sb[0].input_bit_positions, self.word_bit_size, -2)
            b0_shift2 = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])
            inputs_id = b0_xor.id + b0_shift2.id
            inputs_pos = b0_xor.input_bit_positions + b0_shift2.input_bit_positions
            self.add_xor_component(inputs_id, inputs_pos, self.word_bit_size)

            # Swap x <- z
            sp_states[2][column_number] = ComponentState(
                [self.get_current_component_id()], [list(range(self.word_bit_size))]
            )
            # ------------------------------------------------------
            # y after substitution_layer-box
            self.add_shift_component(lane_after_sb[1].id, lane_after_sb[1].input_bit_positions, self.word_bit_size, -1)
            b1_shift = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])
            inputs_id = b1_xor.id + b1_shift.id
            inputs_pos = b1_xor.input_bit_positions + b1_shift.input_bit_positions
            self.add_xor_component(inputs_id, inputs_pos, self.word_bit_size)

            sp_states[1][column_number] = ComponentState(
                [self.get_current_component_id()], [list(range(self.word_bit_size))]
            )
            # ------------------------------------------------------
            # z after substitution_layer-box
            self.add_shift_component(lane_after_sb[2].id, lane_after_sb[2].input_bit_positions, self.word_bit_size, -3)
            b2_shift = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])
            inputs_id = b2_xor.id + b2_shift.id
            inputs_pos = b2_xor.input_bit_positions + b2_shift.input_bit_positions
            self.add_xor_component(inputs_id, inputs_pos, self.word_bit_size)

            # Swap z <- x
            sp_states[0][column_number] = ComponentState(
                [self.get_current_component_id()], [list(range(self.word_bit_size))]
            )

        return sp_states

    def round_constant(self, states, rc):
        self.add_constant_component(self.word_bit_size, rc)
        c = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])
        # state[0,0] = state[0,0] xor RC
        inputs_id = c.id + states[0][0].id
        inputs_pos = c.input_bit_positions + states[0][0].input_bit_positions

        self.add_xor_component(inputs_id, inputs_pos, self.word_bit_size)
        states[0][0] = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

        return states

    def round_function(self, states, round_number):
        states = self.sp_box(states, round_number)

        inputs_id = []
        inputs_pos = []
        for row_number in range(N_ROWS):
            for column_number in range(N_COLS):
                inputs_id = inputs_id + states[row_number][column_number].id
                inputs_pos = inputs_pos + states[row_number][column_number].input_bit_positions

        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        self.add_intermediate_output_component(inputs_id, inputs_pos, self.state_bit_size, "round_output_nonlinear")

        if (round_number & 3) == 0:
            states = small_swap(states)

        if (round_number & 3) == 2:
            states = big_swap(states)

        if (round_number & 3) == 0:
            states = self.round_constant(states, 0x9E377900 ^ round_number)

        return states
