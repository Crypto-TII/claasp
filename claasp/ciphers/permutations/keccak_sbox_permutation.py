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


from copy import deepcopy

from claasp.cipher import Cipher
from claasp.utils.utils import simplify_inputs
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION
from claasp.DTOs.component_state import ComponentState

X_NUM = 5
Y_NUM = 5
SBOX_SIZE = 5
THETA_ROT = -1
PARAMETERS_CONFIGURATION_LIST = [
    {"number_of_rounds": 18, "word_size": 8},
    {"number_of_rounds": 16, "word_size": 16},
    {"number_of_rounds": 20, "word_size": 16},
]
# fmt: off
SBOX = [
    0x00, 0x05, 0x0a, 0x0b, 0x14, 0x11, 0x16, 0x17, 0x09, 0x0c, 0x03, 0x02, 0x0d, 0x08, 0x0f, 0x0e,
    0x12, 0x15, 0x18, 0x1b, 0x06, 0x01, 0x04, 0x07, 0x1a, 0x1d, 0x10, 0x13, 0x1e, 0x19, 0x1c, 0x1f,
]
# fmt: on
ROT_TABLE = [
    [0, -36, -3, -41, -18],
    [-1, -44, -10, -45, -2],
    [-62, -6, -43, -15, -61],
    [-28, -55, -25, -21, -56],
    [-27, -20, -39, -8, -14],
]
ROUND_CONST = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]


class KeccakSboxPermutation(Cipher):
    """
    Construct an instance of the KeccakSboxPermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding.

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `24`); number of rounds of the permutation
        - ``word_size`` -- **integer** (default: `64`); the size of the word

    EXAMPLES::

        sage: from claasp.ciphers.permutations.keccak_sbox_permutation import KeccakSboxPermutation
        sage: keccak = KeccakSboxPermutation(number_of_rounds=24, word_size=64)
        sage: keccak.number_of_rounds
        24

        sage: keccak.component_from(0, 0).id
        'xor_0_0'
    """

    def __init__(self, number_of_rounds=24, word_size=64):
        self.word_bit_size = word_size
        self.plane_size = Y_NUM * self.word_bit_size
        self.state_bit_size = X_NUM * self.plane_size

        super().__init__(
            family_name="keccak_sbox",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        state = self.state_initialization()

        # round function
        for round_number in range(0, number_of_rounds):
            self.add_round()

            # round parameter
            ci = self.get_ci(round_number)
            state = self.round_function(state, ci)

            self.add_output_component(number_of_rounds, round_number, state)

    def add_output_component(self, number_of_rounds, round_number, state):
        inputs_id = []
        inputs_pos = []
        for j in range(Y_NUM):
            for i in range(X_NUM):
                inputs_id = inputs_id + state[i][j].id
                inputs_pos = inputs_pos + state[i][j].input_bit_positions
        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        if round_number == number_of_rounds - 1:
            self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
        else:
            self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def chi_definition(self, b):
        # A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]), for (x,y) in (range(5), range(5))
        p = ComponentState(["" for _ in range(self.word_bit_size)], [[] for _ in range(self.word_bit_size)])
        state_new = [[deepcopy(p) for _ in range(Y_NUM)] for _ in range(X_NUM)]
        for j in range(Y_NUM):
            for k in range(self.word_bit_size):
                inputs_id = []
                inputs_pos = []
                for i in range(X_NUM):
                    inputs_id = inputs_id + b[i][j].id
                    inputs_pos = inputs_pos + [[k]]
                inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
                self.add_SBOX_component(inputs_id, inputs_pos, SBOX_SIZE, SBOX)
                for i in range(X_NUM):
                    state_new[i][j].id[k] = self.get_current_component_id()
                    state_new[i][j].input_bit_positions[k] = [i]
        state = deepcopy(state_new)

        return state

    def get_ci(self, i):
        ci = ROUND_CONST[i]
        ci = ci % (2**self.word_bit_size)

        return ci

    def iota_definition(self, ci, state):
        # create ci constant
        self.add_constant_component(self.word_bit_size, ci)
        c = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])
        # A[0,0] = A[0,0] xor RC
        inputs_id = c.id + state[0][0].id
        inputs_pos = c.input_bit_positions + state[0][0].input_bit_positions
        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        self.add_XOR_component(inputs_id, inputs_pos, self.word_bit_size)
        state[0][0] = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

        return state

    def rho_and_pi_definition(self, state):
        # B[y, 2 * x + 3 * y] = rot(A[x, y], rotate_table[x, y]) for (x, y) in (range(5), range(5))
        b = [[{} for _ in range(Y_NUM)] for _ in range(X_NUM)]
        for i in range(X_NUM):
            for j in range(Y_NUM):
                self.add_rotate_component(
                    state[i][j].id, state[i][j].input_bit_positions, self.word_bit_size, ROT_TABLE[i][j]
                )
                b[j][(2 * i + 3 * j) % Y_NUM] = ComponentState(
                    [self.get_current_component_id()], [list(range(self.word_bit_size))]
                )

        return b

    def round_function(self, state, ci):
        state = self.theta_definition(state)
        b = self.rho_and_pi_definition(state)
        state = self.chi_definition(b)

        return self.iota_definition(ci, state)

    def state_initialization(self):
        state = [[{} for _ in range(Y_NUM)] for _ in range(X_NUM)]
        for i in range(X_NUM):
            for j in range(Y_NUM):
                state[i][j] = ComponentState(
                    [INPUT_PLAINTEXT],
                    [[k + j * self.word_bit_size + i * self.plane_size for k in range(self.word_bit_size)]],
                )

        return state

    def theta_definition(self, state):
        # state = A[x,y], x in range(5), y in range(5)
        # C[x] = Xor (A[x, 0], ..., A[x, 4]) for x in range(5)
        c = []
        for i in range(X_NUM):
            inputs_id = []
            inputs_pos = []
            for j in range(Y_NUM):
                inputs_id = inputs_id + state[i][j].id
                inputs_pos = inputs_pos + state[i][j].input_bit_positions
            inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
            self.add_XOR_component(inputs_id, inputs_pos, self.word_bit_size)
            c.append(ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))]))
        # D[x] = C[x - 1] xor rot(C[x + 1], 1) for x in range(5)
        d = []
        for i in range(X_NUM):
            self.add_rotate_component(
                c[(i + 1) % X_NUM].id, c[(i + 1) % X_NUM].input_bit_positions, self.word_bit_size, THETA_ROT
            )
            inputs_id = c[(i - 1) % X_NUM].id + [self.get_current_component_id()]
            inputs_pos = c[(i - 1) % X_NUM].input_bit_positions + [list(range(self.word_bit_size))]
            self.add_XOR_component(inputs_id, inputs_pos, self.word_bit_size)
            d.append(ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))]))
        # A[x, y] = A[x, y] xor D[x] for x in range(5), y in range(5)
        for i in range(X_NUM):
            for j in range(Y_NUM):
                inputs_id = state[i][j].id + d[i].id
                inputs_pos = state[i][j].input_bit_positions + d[i].input_bit_positions
                self.add_XOR_component(inputs_id, inputs_pos, self.word_bit_size)
                state[i][j] = ComponentState([self.get_current_component_id()], [list(range(self.word_bit_size))])

        return state
