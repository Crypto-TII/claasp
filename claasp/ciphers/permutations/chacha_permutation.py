
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
    1, 5, 9, 13,
    2, 6, 10, 14,
    3, 7, 11, 15
]
DIAGONALS = [
    0, 5, 10, 15,
    1, 6, 11, 12,
    2, 7, 8, 13,
    3, 4, 9, 14
]
PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 20}]


def init_state(state_of_components):
    for i in range(0, 4):
        for j in range(0, 4):
            component_state = ComponentState(
                INPUT_PLAINTEXT, [list(range(j * 32 + i * 128, j * 32 + 32 + i * 128))])
            state_of_components[i][j] = component_state


class ChachaPermutation(Cipher):
    """
    Construct an instance of the ChachaPermutation class.

    This class is used to store compact representations of a permutation, used to generate the corresponding cipher.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `0`); Number of rounds of the permutation. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``state_of_components`` -- **list of lists of integer** (default: `None`)
    - ``cipher_family`` -- **string** (default: `chacha_permutation`)
    - ``cipher_type`` -- **string** (default: `permutation`)
    - ``inputs`` -- **list of integer** (default: `None`)
    - ``cipher_inputs_bit_size`` -- **integer** (default: `None`)

    EXAMPLES::

        sage: from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
        sage: chacha = ChachaPermutation(number_of_rounds=2)
        sage: chacha.number_of_rounds
        2
    """

    def __init__(self, number_of_rounds=0, state_of_components=None,
                 cipher_family="chacha_permutation", cipher_type="permutation",
                 inputs=None, cipher_inputs_bit_size=None):

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
            self.add_round()
            self.half_like_round_function(self.state_of_components, i)
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

    def bottom_half_quarter_round(self, a, b, c, d, state):
        def get_input_bit_positions(component):
            if component.id == 'plaintext':
                return component.input_bit_positions
            else:
                return [list(range(32))]

        def sub_quarter_round(p1_index, p2_index, p3_index, rot_amount):
            p1 = get_2d_array_element_from_1d_array_index(p1_index, state, 4)
            p2 = get_2d_array_element_from_1d_array_index(p2_index, state, 4)
            p3 = get_2d_array_element_from_1d_array_index(p3_index, state, 4)

            p1 = self.add_MODADD_component([p1.id] + [p2.id],
                                           get_input_bit_positions(p1) + get_input_bit_positions(p2),
                                           self.WORD_SIZE)

            p3 = self.add_XOR_component([p3.id] + [p1.id],
                                        get_input_bit_positions(p3) + get_input_bit_positions(p1),
                                        self.WORD_SIZE)

            p3 = self.add_rotate_component([p3.id], get_input_bit_positions(p3), self.WORD_SIZE, rot_amount)
            set_2d_array_element_from_1d_array_index(p1_index, state, p1, 4)
            set_2d_array_element_from_1d_array_index(p3_index, state, p3, 4)

        sub_quarter_round(a, b, d, -8)
        sub_quarter_round(c, d, b, -7)

    def half_like_round_function(self, state, i):
        if (i // 2) % 2 == 0:  # column round
            if i % 2 == 0:
                self.top_half_quarter_round(0, 4, 8, 12, state)
                self.top_half_quarter_round(1, 5, 9, 13, state)
                self.top_half_quarter_round(2, 6, 10, 14, state)
                self.top_half_quarter_round(3, 7, 11, 15, state)
            else:
                self.bottom_half_quarter_round(0, 4, 8, 12, state)
                self.bottom_half_quarter_round(1, 5, 9, 13, state)
                self.bottom_half_quarter_round(2, 6, 10, 14, state)
                self.bottom_half_quarter_round(3, 7, 11, 15, state)

        else:  # diagonal_round
            if i % 2 == 0:
                self.top_half_quarter_round(0, 5, 10, 15, state)
                self.top_half_quarter_round(1, 6, 11, 12, state)
                self.top_half_quarter_round(2, 7, 8, 13, state)
                self.top_half_quarter_round(3, 4, 9, 14, state)
            else:
                self.bottom_half_quarter_round(0, 5, 10, 15, state)
                self.bottom_half_quarter_round(1, 6, 11, 12, state)
                self.bottom_half_quarter_round(2, 7, 8, 13, state)
                self.bottom_half_quarter_round(3, 4, 9, 14, state)

    def quarter_round(self, a, b, c, d, state):
        def get_input_bit_positions(component):
            if component.id == 'plaintext':
                return component.input_bit_positions
            else:
                return [list(range(32))]

        def sub_quarter_round(p1_index, p2_index, p3_index, rot_amount):
            p1 = get_2d_array_element_from_1d_array_index(p1_index, state, 4)
            p2 = get_2d_array_element_from_1d_array_index(p2_index, state, 4)
            p3 = get_2d_array_element_from_1d_array_index(p3_index, state, 4)

            p1 = self.add_MODADD_component([p1.id] + [p2.id],
                                           get_input_bit_positions(p1) + get_input_bit_positions(p2),
                                           self.WORD_SIZE)

            p3 = self.add_XOR_component([p3.id] + [p1.id],
                                        get_input_bit_positions(p3) + get_input_bit_positions(p1),
                                        self.WORD_SIZE)

            p3 = self.add_rotate_component([p3.id], get_input_bit_positions(p3), self.WORD_SIZE, rot_amount)
            set_2d_array_element_from_1d_array_index(p1_index, state, p1, 4)
            set_2d_array_element_from_1d_array_index(p3_index, state, p3, 4)

        sub_quarter_round(a, b, d, -16)
        sub_quarter_round(c, d, b, -12)
        sub_quarter_round(a, b, d, -8)
        sub_quarter_round(c, d, b, -7)

    def round_function(self, state, i):
        if i % 2 == 0:
            self.quarter_round(0, 4, 8, 12, state)
            self.quarter_round(1, 5, 9, 13, state)
            self.quarter_round(2, 6, 10, 14, state)
            self.quarter_round(3, 7, 11, 15, state)
        else:
            self.quarter_round(0, 5, 10, 15, state)
            self.quarter_round(1, 6, 11, 12, state)
            self.quarter_round(2, 7, 8, 13, state)
            self.quarter_round(3, 4, 9, 14, state)

    def top_half_quarter_round(self, a, b, c, d, state):
        def get_input_bit_positions(component):
            if component.id == 'plaintext':
                return component.input_bit_positions
            else:
                return [list(range(32))]

        def sub_quarter_round(p1_index, p2_index, p3_index, rot_amount):
            p1 = get_2d_array_element_from_1d_array_index(p1_index, state, 4)
            p2 = get_2d_array_element_from_1d_array_index(p2_index, state, 4)
            p3 = get_2d_array_element_from_1d_array_index(p3_index, state, 4)

            p1 = self.add_MODADD_component([p1.id] + [p2.id],
                                           get_input_bit_positions(p1) + get_input_bit_positions(p2),
                                           self.WORD_SIZE)
            p3 = self.add_XOR_component([p3.id] + [p1.id],
                                        get_input_bit_positions(p3) + get_input_bit_positions(p1),
                                        self.WORD_SIZE)

            p3 = self.add_rotate_component([p3.id], get_input_bit_positions(p3), self.WORD_SIZE, rot_amount)
            set_2d_array_element_from_1d_array_index(p1_index, state, p1, 4)
            set_2d_array_element_from_1d_array_index(p3_index, state, p3, 4)

        sub_quarter_round(a, b, d, -16)
        sub_quarter_round(c, d, b, -12)
