
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
from claasp.ciphers.permutations.util import sub_quarter_round_latin_dances, init_latin_dances_cipher
from claasp.name_mappings import INPUT_PLAINTEXT

COLUMNS = [
    [0, 4, 8, 12],
    [5, 9, 13, 1],
    [10, 14, 2, 6],
    [15, 3, 7, 11]
]
DIAGONALS = [
    [0, 1, 2, 3],
    [5, 6, 7, 4],
    [10, 11, 8, 9],
    [15, 12, 13, 14]
]
PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 20}]


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
    - ``rotations`` -- *list of integer* (default: `[8, 7, 16, 12]`)
    - ``word_size`` --  **integer** (default: `32`)
    - ``start_round`` --  **string** (default: `odd`)

    EXAMPLES::

        sage: from claasp.ciphers.permutations.salsa_permutation import SalsaPermutation
        sage: salsa = SalsaPermutation(number_of_rounds=2)
        sage: salsa.number_of_rounds
        2
    """

    def __init__(self, number_of_rounds=0, state_of_components=None,
                 cipher_family="salsa_permutation", cipher_type="permutation",
                 inputs=None, cipher_inputs_bit_size=None,
                 rotations=[13, 18, 7, 9],
                 word_size=32, start_round="odd"):
        init_latin_dances_cipher(
            self, super(), INPUT_PLAINTEXT, state_of_components, number_of_rounds,
            start_round, cipher_family, cipher_type, inputs, cipher_inputs_bit_size, [COLUMNS, DIAGONALS],
            word_size, rotations
        )

    def top_half_quarter_round(self, a, b, c, d, state):
        sub_quarter_round_latin_dances(self, state, a, d, b, -self.rotation_3, 'salsa')
        sub_quarter_round_latin_dances(self, state, a, b, c, -self.rotation_4, 'salsa')

    def bottom_half_quarter_round(self, a, b, c, d, state):
        sub_quarter_round_latin_dances(self, state, b, c, d, -self.rotation_1, 'salsa')
        sub_quarter_round_latin_dances(self, state, c, d, a, -self.rotation_2, 'salsa')
