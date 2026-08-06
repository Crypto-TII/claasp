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
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION
from claasp.ciphers.permutations.util import (
    init_state_latin_dances,
    get_2d_array_element_from_1d_array_index,
    set_2d_array_element_from_1d_array_index,
    get_input_bit_positions_latin_dances,
    add_intermediate_output_component_latin_dances_permutations,
)

COLUMNS = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]]
DIAGONALS = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]]
POLLINATION_INDICES = [3, 0, 1, 2]

PARAMETERS_CONFIGURATION_LIST = [
    {"number_of_rounds": 14},
    {"number_of_rounds": 10},
]

class ForroPermutation(Cipher):
    """
    Construct an instance of the ForroPermutation class.

    This class is used to store compact representations of a permutation, used to generate the
    corresponding cipher. It implements the Forró permutation proposed in [CPV+22]_.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `14`); number of rounds of the permutation.
    - ``state_of_components`` -- **list of lists of integer** (default: `None`)
    - ``inputs`` -- **list of integer** (default: `None`)
    - ``cipher_inputs_bit_size`` -- **integer** (default: `None`)
    - ``rotations`` -- **list of integer** (default: `[10, 27, 8]`)
    - ``word_size`` -- **integer** (default: `32`)

    EXAMPLES::

        sage: from claasp.ciphers.permutations.forro_permutation import ForroPermutation
        sage: forro = ForroPermutation(number_of_rounds=2)
        sage: forro.number_of_rounds
        2
    """

    def __init__(
        self,
        number_of_rounds=14,
        state_of_components=None,
        inputs=None,
        cipher_inputs_bit_size=None,
        rotations=[10, 27, 8],
        word_size=32,
    ):
        self.block_bit_size = word_size * 16
        self.WORD_SIZE = word_size
        self.rotation_1 = rotations[0]
        self.rotation_2 = rotations[1]
        self.rotation_3 = rotations[2]
        self.nrounds = number_of_rounds

        super().__init__(
            family_name="forro_permutation",
            cipher_type=PERMUTATION,
            cipher_inputs=inputs if inputs else [INPUT_PLAINTEXT],
            cipher_inputs_bit_size=cipher_inputs_bit_size if inputs else [self.block_bit_size],
            cipher_output_bit_size=self.block_bit_size,
        )

        if state_of_components is None:
            self.state_of_components = [
                [None, None, None, None],
                [None, None, None, None],
                [None, None, None, None],
                [None, None, None, None],
            ]
            init_state_latin_dances(self, INPUT_PLAINTEXT)
        else:
            self.state_of_components = state_of_components

        for round_index in range(number_of_rounds):
            self.add_round()
            self._round_function(round_index)
            add_intermediate_output_component_latin_dances_permutations(self, round_index, number_of_rounds)

    def _round_function(self, round_index):
        group = COLUMNS if round_index % 2 == 0 else DIAGONALS

        for i in range(4):
            p_a, p_b, p_c, p_d = group[i]
            p_e = group[POLLINATION_INDICES[i]][0]
            self._subround_forro(p_a, p_b, p_c, p_d, p_e)

    def _subround_forro(self, p_a, p_b, p_c, p_d, p_e):
        state = self.state_of_components
        ws = self.WORD_SIZE

        a = get_2d_array_element_from_1d_array_index(p_a, state, 4)
        b = get_2d_array_element_from_1d_array_index(p_b, state, 4)
        c = get_2d_array_element_from_1d_array_index(p_c, state, 4)
        d = get_2d_array_element_from_1d_array_index(p_d, state, 4)
        e = get_2d_array_element_from_1d_array_index(p_e, state, 4)

        d = self._modadd(d, e, ws)
        c = self._xor(c, d, ws)
        b = self._modadd(b, c, ws)
        b = self._rotate(b, ws, -self.rotation_1)
        a = self._modadd(a, b, ws)
        e = self._xor(e, a, ws)
        d = self._modadd(d, e, ws)
        d = self._rotate(d, ws, -self.rotation_2)
        c = self._modadd(c, d, ws)
        b = self._xor(b, c, ws)
        a = self._modadd(a, b, ws)
        a = self._rotate(a, ws, -self.rotation_3)

        set_2d_array_element_from_1d_array_index(p_a, state, a, 4)
        set_2d_array_element_from_1d_array_index(p_b, state, b, 4)
        set_2d_array_element_from_1d_array_index(p_c, state, c, 4)
        set_2d_array_element_from_1d_array_index(p_d, state, d, 4)
        set_2d_array_element_from_1d_array_index(p_e, state, e, 4)

    def _modadd(self, x, y, word_size):
        return self.add_modadd_component(
            [x.id, y.id],
            get_input_bit_positions_latin_dances(x, word_size) + get_input_bit_positions_latin_dances(y, word_size),
            word_size,
        )

    def _xor(self, x, y, word_size):
        return self.add_xor_component(
            [x.id, y.id],
            get_input_bit_positions_latin_dances(x, word_size) + get_input_bit_positions_latin_dances(y, word_size),
            word_size,
        )

    def _rotate(self, x, word_size, rot_amount):
        return self.add_rotate_component(
            [x.id],
            get_input_bit_positions_latin_dances(x, word_size),
            word_size,
            rot_amount,
        )