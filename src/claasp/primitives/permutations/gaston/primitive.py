"""Canonical Gaston permutation construction."""

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
from claasp.primitive_inputs import INPUT_PLAINTEXT, PERMUTATION

GASTON_NROWS = 5
WORD_SIZE = 64

# parameters for theta
GASTON_t = [25, 32, 52, 60, 63]
# GASTON_t0 = 25
# GASTON_t1 = 32
# GASTON_t2 = 52
# GASTON_t3 = 60
# GASTON_t4 = 63

GASTON_r = 1
GASTON_s = 18
GASTON_u = 23

# rho-east rotation offsets
GASTON_e = [0, 60, 22, 27, 4]
# GASTON_e0 = 0
# GASTON_e1 = 60
# GASTON_e2 = 22
# GASTON_e3 = 27
# GASTON_e4 = 4

# rho-west rotation offsets
GASTON_w = [0, 56, 31, 46, 43]
# GASTON_w0 = 0
# GASTON_w1 = 56
# GASTON_w2 = 31
# GASTON_w3 = 46
# GASTON_w4 = 43

# gaston round constant
gaston_rc = [0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B]

PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 12}]


class Gaston(BitGraphPrimitive):
    """
    Construct an instance of the Gaston Permutation class.

    The permutation parameters and reference implementation are specified in [GASTON2023]_.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `12`); number of rounds of the permutation

    EXAMPLES::

        >>> primitive = Gaston()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x88b326096bebc635', 320)
    """

    def __init__(self, number_of_rounds=12):
        self.state_bit_size = GASTON_NROWS * WORD_SIZE

        super().__init__(
            family_name="gaston",
            primitive_type=PERMUTATION,
            primitive_inputs=[INPUT_PLAINTEXT],
            primitive_inputs_bit_size=[self.state_bit_size],
            primitive_output_bit_size=self.state_bit_size,
        )

        # gaston state initialization
        state = []
        for row in range(GASTON_NROWS):
            p = BitState([INPUT_PLAINTEXT], [[i + row * WORD_SIZE for i in range(WORD_SIZE)]])
            state.append(p)

        for round_number in range(12 - number_of_rounds, 12):
            self._builder.add_round()
            # gaston round function
            state = self.gaston_round_function(state, gaston_rc[round_number])
            # gaston round output
            inputs_id, inputs_pos = get_inputs_parameter([state[i] for i in range(GASTON_NROWS)])
            if round_number == 11:
                self.add_primitive_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def gaston_round_function(self, state, rc):
        """Build the gaston round function stage in this primitive's typed operation graph."""
        state = self.gaston_rho_east(state)
        state = self.gaston_theta(state)
        state = self.gaston_rho_west(state)
        state = self.gaston_iota(state, rc)
        state = self.gaston_chi(state)

        return state

    def gaston_rho_east(self, state):
        """Build the gaston rho east stage in this primitive's typed operation graph."""
        for row in range(GASTON_NROWS):
            self.add_rotate_component(
                state[row].id, state[row].input_bit_positions, WORD_SIZE, -GASTON_e[row]
            )
            state[row] = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state

    def gaston_theta(self, state):
        """Build the gaston theta stage in this primitive's typed operation graph."""
        inputs_id, inputs_pos = get_inputs_parameter([state[i] for i in range(GASTON_NROWS)])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        P = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        self.add_rotate_component(P.id, P.input_bit_positions, WORD_SIZE, -GASTON_r)
        P_rot = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([P, P_rot])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        P = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        # column parity P

        Q_rows = []
        for i in range(GASTON_NROWS):
            self.add_rotate_component(
                state[i].id, state[i].input_bit_positions, WORD_SIZE, -GASTON_t[i]
            )
            q = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])
            Q_rows.append(q)

        inputs_id, inputs_pos = get_inputs_parameter([Q_rows[i] for i in range(GASTON_NROWS)])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        Q = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        self.add_rotate_component(Q.id, Q.input_bit_positions, WORD_SIZE, -GASTON_s)
        Q_rot = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        inputs_id, inputs_pos = get_inputs_parameter([Q, Q_rot])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        Q = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        # column parity Q

        inputs_id, inputs_pos = get_inputs_parameter([P, Q])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        P = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        self.add_rotate_component(P.id, P.input_bit_positions, WORD_SIZE, -GASTON_u)
        P = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        for row in range(GASTON_NROWS):
            inputs_id, inputs_pos = get_inputs_parameter([state[row], P])
            self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
            state[row] = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state

    def gaston_rho_west(self, state):
        """Build the gaston rho west stage in this primitive's typed operation graph."""
        for row in range(GASTON_NROWS):
            self.add_rotate_component(
                state[row].id, state[row].input_bit_positions, WORD_SIZE, -GASTON_w[row]
            )
            state[row] = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state

    def gaston_iota(self, state, rc):
        """Build the gaston iota stage in this primitive's typed operation graph."""
        self.add_constant_component(WORD_SIZE, rc)
        const = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[0], const])
        self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
        state[0] = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state

    def gaston_chi(self, state):
        """Build the gaston chi stage in this primitive's typed operation graph."""
        not_comp = [None] * GASTON_NROWS
        for row in range(GASTON_NROWS):
            self.add_not_component(state[row].id, state[row].input_bit_positions, WORD_SIZE)
            not_comp[row] = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        and_comp = [None] * GASTON_NROWS
        for row in range(GASTON_NROWS):
            inputs_id, inputs_pos = get_inputs_parameter(
                [state[(row + 2) % GASTON_NROWS], not_comp[(row + 1) % GASTON_NROWS]]
            )
            self.add_and_component(inputs_id, inputs_pos, WORD_SIZE)
            and_comp[row] = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        for row in range(GASTON_NROWS):
            inputs_id, inputs_pos = get_inputs_parameter([state[row], and_comp[row]])
            self.add_xor_component(inputs_id, inputs_pos, WORD_SIZE)
            state[row] = BitState([self.get_current_component_id()], [list(range(WORD_SIZE))])

        return state
