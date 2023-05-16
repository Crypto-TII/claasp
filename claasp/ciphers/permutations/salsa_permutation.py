
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
from claasp.name_mappings import INPUT_PLAINTEXT
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import get_2d_array_element_from_1d_array_index, set_2d_array_element_from_1d_array_index

COLUMNS = [
    0, 4, 8, 12,
    5, 9, 13, 1,
    10, 14, 2, 6,
    15, 3, 7, 11
]
DIAGONALS = [
    0, 1, 2, 3,
    5, 6, 7, 4,
    10, 11, 8, 9,
    15, 12, 13, 14
]
PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 20}]


def init_state(state_of_components):
    for i in range(0, 4):
        for j in range(0, 4):
            component_state = ComponentState(
                INPUT_PLAINTEXT, [list(range(j * 32 + i * 128, j * 32 + 32 + i * 128))])
            state_of_components[i][j] = component_state


class SalsaPermutation(Cipher):
    """
    Construct an instance of the SalsaPermutation class.

    This class is used to store compact representations of a permutation, used to generate the corresponding cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `0`); Number of rounds of the permutation. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``state_of_components`` -- **list of lists of integer** (default: `None`)
    - ``cipher_family`` -- **string** (default: `salsa_permutation`)
    - ``cipher_type`` -- **string** (default: `permutation`)
    - ``inputs`` -- **list of integer** (default: `None`)
    - ``cipher_inputs_bit_size`` -- **integer** (default: `None`)

    EXAMPLES::

        sage: from claasp.ciphers.permutations.salsa_permutation import SalsaPermutation
        sage: salsa = SalsaPermutation(number_of_rounds=2)
        sage: salsa.number_of_rounds
        2
    """

    def __init__(self, number_of_rounds=0, state_of_components=None,
                 cipher_family="salsa_permutation", cipher_type="permutation",
                 inputs=None, cipher_inputs_bit_size=None, start_round="odd"):

        self.block_bit_size = 512
        self.WORD_SIZE = 32

        if state_of_components is None:
            self.state_of_components = [
                [None, None, None, None],
                [None, None, None, None],
                [None, None, None, None],
                [None, None, None, None],
            ]
            init_state(self.state_of_components)
        else:
            self.state_of_components = state_of_components

        super().__init__(family_name=cipher_family,
                         cipher_type=cipher_type,
                         cipher_inputs=inputs if inputs else [INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=cipher_inputs_bit_size if inputs else [self.block_bit_size],
                         cipher_output_bit_size=self.block_bit_size)

        for i in range(number_of_rounds):
            if start_round == 'even':
                j = i + 2
            else:
                j = i
            self.add_round()
            self.half_like_round_function(self.state_of_components, j)
            self.add_intermediate_output_components(self.state_of_components, i, number_of_rounds)

    def add_intermediate_output_components(self, internal_state, round_i, number_of_rounds):
        lst_ids = []
        lst_input_input_positions = []
        for i in range(4):
            for j in range(4):
                lst_ids.append(internal_state[i][j].id)
                lst_input_input_positions.append(list(range(32)))
        if round_i == number_of_rounds - 1:
            self.add_cipher_output_component(lst_ids, lst_input_input_positions, self.block_bit_size)
        else:
            self.add_round_output_component(lst_ids, lst_input_input_positions, self.block_bit_size)

    def sub_quarter_round(self, state, p1_index, p2_index, p3_index, rot_amount):
        def get_input_bit_positions(component):
            if component.id == 'plaintext':
                return component.input_bit_positions
            else:
                return [list(range(32))]
        p1 = get_2d_array_element_from_1d_array_index(p1_index, state, 4)
        p2 = get_2d_array_element_from_1d_array_index(p2_index, state, 4)
        p3 = get_2d_array_element_from_1d_array_index(p3_index, state, 4)

        p1 = self.add_MODADD_component([p1.id] + [p2.id],
                                       get_input_bit_positions(p1) + get_input_bit_positions(p2),
                                       self.WORD_SIZE)
        p2 = self.add_rotate_component([p1.id], get_input_bit_positions(p1), self.WORD_SIZE, rot_amount)
        p3 = self.add_XOR_component([p3.id] + [p2.id],
                                    get_input_bit_positions(p3) + get_input_bit_positions(p2),
                                    self.WORD_SIZE)

        set_2d_array_element_from_1d_array_index(p3_index, state, p3, 4)

    def bottom_half_quarter_round(self, a, b, c, d, state):
        self.sub_quarter_round(state, b, c, d, -13)
        self.sub_quarter_round(state, c, d, a, -18)

    def top_half_quarter_round(self, a, b, c, d, state):
        self.sub_quarter_round(state, a, d, b, -7)
        self.sub_quarter_round(state, a, b, c, -9)

    def half_like_round_function(self, state, i):
        if (i // 2) % 2 == 0:  # column round
            if i % 2 == 0:
                self.top_half_quarter_round(0,  4,  8,  12, state)
                self.top_half_quarter_round(5,  9,  13, 1, state)
                self.top_half_quarter_round(10, 14, 2,  6, state)
                self.top_half_quarter_round(15, 3,  7,  11, state)
            else:
                self.bottom_half_quarter_round(0, 4, 8, 12, state)
                self.bottom_half_quarter_round(5, 9, 13, 1, state)
                self.bottom_half_quarter_round(10, 14, 2, 6, state)
                self.bottom_half_quarter_round(15, 3, 7, 11, state)

        else:  # row_round
            if i % 2 == 0:
                self.top_half_quarter_round(0, 1, 2, 3, state)
                self.top_half_quarter_round(5, 6, 7, 4, state)
                self.top_half_quarter_round(10, 11, 8, 9, state)
                self.top_half_quarter_round(15, 12, 13, 14, state)
            else:
                self.bottom_half_quarter_round(0, 1, 2, 3, state)
                self.bottom_half_quarter_round(5, 6, 7, 4, state)
                self.bottom_half_quarter_round(10, 11, 8, 9, state)
                self.bottom_half_quarter_round(15, 12, 13, 14, state)
