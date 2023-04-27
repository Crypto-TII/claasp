
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
from claasp.name_mappings import INPUT_PLAINTEXT
from claasp.DTOs.component_state import ComponentState

X_NUM = 5
Y_NUM = 5
SBOX_SIZE = 5
THETA_ROT = -1
PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 18, 'word_size': 8},
                                 {'number_of_rounds': 16, 'word_size': 16},
                                 {'number_of_rounds': 20, 'word_size': 16}]
SBOX = [0, 5, 10, 11, 20, 17, 22, 23, 9, 12, 3, 2, 13, 8, 15, 14,
        18, 21, 24, 27, 6, 1, 4, 7, 26, 29, 16, 19, 30, 25, 28, 31]
ROT_TABLE = [
    [0, -36, -3, -41, -18],
    [-1, -44, -10, -45, -2],
    [-62, -6, -43, -15, -61],
    [-28, -55, -25, -21, -56],
    [-27, -20, -39, -8, -14]
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
    0x8000000080008008
]


class KeccakInvertiblePermutation(Cipher):
    """
    Construct an instance of the KeccakInvertiblePermutation class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

    INPUT:

        - ``number_of_rounds`` -- **integer** (default: `24`); number of rounds of the permutation
        - ``word_size`` -- **integer** (default: `64`); the size of the word

    EXAMPLES::

        sage: from claasp.ciphers.permutations.keccak_invertible_permutation import KeccakInvertiblePermutation
        sage: keccak = KeccakInvertiblePermutation(number_of_rounds=3, word_size=64)
        sage: keccak.number_of_rounds
        3

        sage: keccak.component_from(0, 0).id
        'theta_keccak_0_0'
    """

    def __init__(self, number_of_rounds=24, word_size=64):
        self.word_bit_size = word_size
        self.plane_size = Y_NUM * self.word_bit_size
        self.state_bit_size = X_NUM * self.plane_size

        super().__init__(family_name="keccak_invertible",
                         cipher_type="permutation",
                         cipher_inputs=[INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[self.state_bit_size],
                         cipher_output_bit_size=self.state_bit_size)

        state = self.state_initialization()

        # round function
        for round_number in range(0, number_of_rounds):
            self.add_round()

            # round parameter
            ci = self.get_ci(round_number)
            state = self.round_function(state, ci, word_size)

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
        ci = ci % (2 ** self.word_bit_size)

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
                self.add_rotate_component(state[i][j].id, state[i][j].input_bit_positions, self.word_bit_size,
                                          ROT_TABLE[i][j])
                b[j][(2 * i + 3 * j) % Y_NUM] = ComponentState([self.get_current_component_id()],
                                                               [list(range(self.word_bit_size))])

        return b

    def round_function(self, state, ci, word_size):
        state = self.theta_definition(state, word_size)
        b = self.rho_and_pi_definition(state)
        state = self.chi_definition(b)

        return self.iota_definition(ci, state)

    def state_initialization(self):
        state = [[{} for _ in range(Y_NUM)] for _ in range(X_NUM)]
        for i in range(X_NUM):
            for j in range(Y_NUM):
                state[i][j] = ComponentState([INPUT_PLAINTEXT],
                                             [[k + j * self.word_bit_size + i * self.plane_size for k in
                                               range(self.word_bit_size)]])

        return state

    def theta_definition(self, state, word_size):
        inputs_id = []
        inputs_pos = []
        for i in range(X_NUM):
            for j in range(Y_NUM):
                inputs_id = inputs_id + state[i][j].id
                inputs_pos = inputs_pos + state[i][j].input_bit_positions
        self.add_theta_keccak_component(inputs_id, inputs_pos, X_NUM * Y_NUM * word_size)
        state = []
        for i in range(X_NUM):
            tmp = []
            for j in range(Y_NUM):
                tmp.append(ComponentState([self.get_current_component_id()],
                                          [[k + j * word_size + i * word_size * X_NUM for k in range(word_size)]]))
            state.append(tmp)

        return state
