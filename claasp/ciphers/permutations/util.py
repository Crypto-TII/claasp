
# ****************************************************************************
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
from claasp.utils.utils import get_2d_array_element_from_1d_array_index, set_2d_array_element_from_1d_array_index


def add_intermediate_output_component_latin_dances_permutations(permutation, round_i, number_of_rounds):
    lst_ids = []
    lst_input_input_positions = []
    internal_state = permutation.state_of_components
    for i in range(4):
        for j in range(4):
            lst_ids.append(internal_state[i][j].id)
            lst_input_input_positions.append(list(range(32)))
    if round_i == number_of_rounds - 1:
        permutation.add_cipher_output_component(lst_ids, lst_input_input_positions, permutation.block_bit_size)
    else:
        permutation.add_round_output_component(lst_ids, lst_input_input_positions, permutation.block_bit_size)


def half_like_round_function_latin_dances(permutation, round_number, columns, diagonals):
    state = permutation.state_of_components

    def top_half_quarter_round(a, b, c, d):
        permutation.top_half_quarter_round(*a, state)
        permutation.top_half_quarter_round(*b, state)
        permutation.top_half_quarter_round(*c, state)
        permutation.top_half_quarter_round(*d, state)

    def bottom_half_quarter_round(a, b, c, d):
        permutation.bottom_half_quarter_round(*a, state)
        permutation.bottom_half_quarter_round(*b, state)
        permutation.bottom_half_quarter_round(*c, state)
        permutation.bottom_half_quarter_round(*d, state)

    if (round_number // 2) % 2 == 0:  # column round
        if round_number % 2 == 0:
            top_half_quarter_round(columns[0], columns[1], columns[2], columns[3])
        else:
            bottom_half_quarter_round(columns[0], columns[1], columns[2], columns[3])

    else:  # row_round
        if round_number % 2 == 0:
            top_half_quarter_round(diagonals[0], diagonals[1], diagonals[2], diagonals[3])
        else:
            bottom_half_quarter_round(diagonals[0], diagonals[1], diagonals[2], diagonals[3])


def sub_quarter_round_latin_dances(permutation, state, p1_index, p2_index, p3_index, rot_amount, cipher_name):
    p1 = get_2d_array_element_from_1d_array_index(p1_index, state, 4)
    p2 = get_2d_array_element_from_1d_array_index(p2_index, state, 4)
    p3 = get_2d_array_element_from_1d_array_index(p3_index, state, 4)

    p1 = permutation.add_MODADD_component([p1.id] + [p2.id], get_input_bit_positions_latin_dances(p1) +
                                          get_input_bit_positions_latin_dances(p2), permutation.WORD_SIZE)
    if cipher_name == 'salsa':
        p2 = permutation.add_rotate_component([p1.id], get_input_bit_positions_latin_dances(p1), permutation.WORD_SIZE,
                                              rot_amount)
        p3 = permutation.add_XOR_component([p3.id] + [p2.id], get_input_bit_positions_latin_dances(p3) +
                                           get_input_bit_positions_latin_dances(p2), permutation.WORD_SIZE)

        set_2d_array_element_from_1d_array_index(p3_index, state, p3, 4)
    else:
        p3 = permutation.add_XOR_component([p3.id] + [p1.id], get_input_bit_positions_latin_dances(p3) +
                                           get_input_bit_positions_latin_dances(p1), permutation.WORD_SIZE)

        p3 = permutation.add_rotate_component([p3.id], get_input_bit_positions_latin_dances(p3), permutation.WORD_SIZE,
                                              rot_amount)
        set_2d_array_element_from_1d_array_index(p1_index, state, p1, 4)
        set_2d_array_element_from_1d_array_index(p3_index, state, p3, 4)


def get_input_bit_positions_latin_dances(component):
    if component.id == 'plaintext':
        return component.input_bit_positions
    else:
        return [list(range(32))]


def init_state_latin_dances(state_of_components, input_plaintext):
    for i in range(0, 4):
        for j in range(0, 4):
            component_state = ComponentState(
                input_plaintext, [list(range(j * 32 + i * 128, j * 32 + 32 + i * 128))])
            state_of_components[i][j] = component_state


def init_latin_dances_cipher(
        permutation, super, input_plaintext, state_of_components, number_of_rounds,
        start_round, cipher_family, cipher_type, inputs, cipher_inputs_bit_size, columns, diagonals
):
    permutation.block_bit_size = 512
    permutation.WORD_SIZE = 32

    if state_of_components is None:
        permutation.state_of_components = [
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
        ]
        init_state_latin_dances(permutation.state_of_components, input_plaintext)
    else:
        permutation.state_of_components = state_of_components

    super.__init__(family_name=cipher_family,
                     cipher_type=cipher_type,
                     cipher_inputs=inputs if inputs else [input_plaintext],
                     cipher_inputs_bit_size=cipher_inputs_bit_size if inputs else [permutation.block_bit_size],
                     cipher_output_bit_size=permutation.block_bit_size)

    for i in range(number_of_rounds):
        if start_round == 'even':
            j = i + 2
        else:
            j = i
        permutation.add_round()
        half_like_round_function_latin_dances(permutation, j, columns, diagonals)
        add_intermediate_output_component_latin_dances_permutations(permutation, i, number_of_rounds)
