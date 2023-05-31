
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


from claasp.cipher import Cipher
from claasp.ciphers.permutations.util import sub_quarter_round_latin_dances, init_latin_dances_cipher
from claasp.name_mappings import INPUT_PLAINTEXT

COLUMNS = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15]
]
DIAGONALS = [
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14]
]
PARAMETERS_CONFIGURATION_LIST = [{'number_of_rounds': 20}]


class ChachaPermutation(Cipher):
    """
    Construct an instance of the ChachaPermutation class.

    This class is used to store compact representations of a permutation, used to generate the corresponding cipher.
    Additionally, one can use this class to implement ChaCha toy ciphers, such as the one described in [DEY2023]_.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `0`); Number of rounds of the permutation. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0
    - ``state_of_components`` -- **list of lists of integer** (default: `None`)
    - ``cipher_family`` -- **string** (default: `chacha_permutation`)
    - ``cipher_type`` -- **string** (default: `permutation`)
    - ``inputs`` -- **list of integer** (default: `None`)
    - ``cipher_inputs_bit_size`` -- **integer** (default: `None`)
    - ``rotations`` -- *list of integer* (default: `[8, 7, 16, 12]`)
    - ``word_size`` --  **integer** (default: `32`)
    - ``start_round`` --  **string** (default: `odd`)

    EXAMPLES::

        sage: from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
        sage: chacha = ChachaPermutation(number_of_rounds=2)
        sage: chacha.number_of_rounds
        2
    """

    def __init__(self, number_of_rounds=0, state_of_components=None,
                 cipher_family="chacha_permutation", cipher_type="permutation",
                 inputs=None, cipher_inputs_bit_size=None,
                 rotations=[8, 7, 16, 12],
                 word_size=32, start_round="odd"):
        init_latin_dances_cipher(
            self, super(), INPUT_PLAINTEXT, state_of_components, number_of_rounds,
            start_round, cipher_family, cipher_type, inputs, cipher_inputs_bit_size, [COLUMNS, DIAGONALS],
            word_size, rotations
        )

    def top_half_quarter_round(self, a, b, c, d, state):
        sub_quarter_round_latin_dances(self, state, a, b, d, -self.rotation_3, 'chacha')
        sub_quarter_round_latin_dances(self, state, c, d, b, -self.rotation_4, 'chacha')

    def bottom_half_quarter_round(self, a, b, c, d, state):
        sub_quarter_round_latin_dances(self, state, a, b, d, -self.rotation_1, 'chacha')
        sub_quarter_round_latin_dances(self, state, c, d, b, -self.rotation_2, 'chacha')
