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
from claasp.name_mappings import INPUT_PLAINTEXT
from claasp.utils.utils import get_2d_array_element_from_1d_array_index, set_2d_array_element_from_1d_array_index


def print_state_ids(state):
    str_state = ""
    for i in range(4):
        str_temp = ""
        for j in range(4):
            str_temp += state[i][j].id + " "
        print(str_temp + "\n")
    str_state += str_temp
    print(str_state)


def add_intermediate_output_component_latin_dances_permutations(permutation, round_i, number_of_rounds):
    lst_ids = []
    lst_input_input_positions = []
    internal_state = permutation.state_of_components
    for i in range(4):
        for j in range(4):
            lst_ids.append(internal_state[i][j].id)
            lst_input_input_positions.append(list(range(permutation.WORD_SIZE)))
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


_QUARTER_STAGE_METHODS = (
    "first_quarter_round",
    "second_quarter_round",
    "third_quarter_round",
    "fourth_quarter_round",
)


def quarter_like_round_function_latin_dances(permutation, quarter_number, columns, diagonals):
    """
    Single-modular-addition granularity: each call performs exactly one of the four ARX
    stages that together make up a full column/diagonal round (``half_half`` round mode).
    """
    state = permutation.state_of_components
    stage_method = getattr(permutation, _QUARTER_STAGE_METHODS[quarter_number % 4])
    groups = columns if (quarter_number // 4) % 2 == 0 else diagonals

    for group in groups:
        stage_method(*group, state)


def sub_quarter_round_latin_dances(permutation, state, p1_index, p2_index, p3_index, rot_amount, cipher_name):
    p1 = get_2d_array_element_from_1d_array_index(p1_index, state, 4)
    p2 = get_2d_array_element_from_1d_array_index(p2_index, state, 4)
    p3 = get_2d_array_element_from_1d_array_index(p3_index, state, 4)
    word_size = permutation.WORD_SIZE

    p1 = permutation.add_modadd_component(
        [p1.id] + [p2.id],
        get_input_bit_positions_latin_dances(p1, word_size) + get_input_bit_positions_latin_dances(p2, word_size),
        word_size,
    )
    if cipher_name == "salsa":
        p2 = permutation.add_rotate_component(
            [p1.id], get_input_bit_positions_latin_dances(p1, word_size), word_size, rot_amount
        )
        p3 = permutation.add_xor_component(
            [p3.id] + [p2.id],
            get_input_bit_positions_latin_dances(p3, word_size) + get_input_bit_positions_latin_dances(p2, word_size),
            word_size,
        )

        set_2d_array_element_from_1d_array_index(p3_index, state, p3, 4)
    else:
        p3 = permutation.add_xor_component(
            [p3.id] + [p1.id],
            get_input_bit_positions_latin_dances(p3, word_size) + get_input_bit_positions_latin_dances(p1, word_size),
            word_size,
        )

        p3 = permutation.add_rotate_component(
            [p3.id], get_input_bit_positions_latin_dances(p3, word_size), word_size, rot_amount
        )
        set_2d_array_element_from_1d_array_index(p1_index, state, p1, 4)
        set_2d_array_element_from_1d_array_index(p3_index, state, p3, 4)


def get_input_bit_positions_latin_dances(component, word_size=32):
    if component.id == INPUT_PLAINTEXT:
        return component.input_bit_positions
    else:
        return [list(range(word_size))]


def init_state_latin_dances(permutation, input_plaintext):
    state_of_components = permutation.state_of_components
    word_size = permutation.WORD_SIZE
    for i in range(0, 4):
        for j in range(0, 4):
            i_offset = 4 * word_size
            component_state = ComponentState(
                input_plaintext, [list(range(j * word_size + i * i_offset, j * word_size + word_size + i * i_offset))]
            )
            state_of_components[i][j] = component_state


_QUARTER_START_STAGES = {
    "top": 0,
    "top_first": 0,
    "top_second": 1,
    "bottom": 2,
    "bottom_first": 2,
    "bottom_second": 3,
}


def init_latin_dances_cipher(
    permutation,
    super_class,
    input_plaintext,
    state_of_components,
    number_of_rounds,
    start_round,
    cipher_family,
    cipher_type,
    inputs,
    cipher_inputs_bit_size,
    quarter_round_indexes,
    word_size,
    rotations,
    round_granularity=2,
):
    columns = quarter_round_indexes[0]
    diagonals = quarter_round_indexes[1]
    permutation.block_bit_size = word_size * 16
    permutation.WORD_SIZE = word_size
    permutation.rotation_1 = rotations[0]
    permutation.rotation_2 = rotations[1]
    permutation.rotation_3 = rotations[2]
    permutation.rotation_4 = rotations[3]

    if state_of_components is None:
        permutation.state_of_components = [
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
        ]
        init_state_latin_dances(permutation, input_plaintext)
    else:
        permutation.state_of_components = state_of_components

    super_class.__init__(
        family_name=cipher_family,
        cipher_type=cipher_type,
        cipher_inputs=inputs if inputs else [input_plaintext],
        cipher_inputs_bit_size=cipher_inputs_bit_size if inputs else [permutation.block_bit_size],
        cipher_output_bit_size=permutation.block_bit_size,
    )

    for i in range(number_of_rounds):
        if round_granularity == 4:
            j = i + 4 if start_round[0] == "even" else i
            stage_label = start_round[1] if len(start_round) > 1 else "top"
            if stage_label not in _QUARTER_START_STAGES:
                raise ValueError(
                    "start_round[1] must be one of "
                    "'top' ('top_first'), 'top_second', 'bottom' ('bottom_first') or 'bottom_second' "
                    "when round_granularity is 4"
                )
            j += _QUARTER_START_STAGES[stage_label]
            permutation.add_round()
            quarter_like_round_function_latin_dances(permutation, j, columns, diagonals)
        else:
            if start_round[0] == "even":
                j = i + 2
            else:
                j = i
            if start_round[1] == "bottom":
                j += 1
            permutation.add_round()
            half_like_round_function_latin_dances(permutation, j, columns, diagonals)
        add_intermediate_output_component_latin_dances_permutations(permutation, i, number_of_rounds)
