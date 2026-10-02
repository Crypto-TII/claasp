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
from claasp.ciphers.permutations.util import init_latin_dances_cipher, sub_quarter_round_latin_dances
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

COLUMNS = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]]
DIAGONALS = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]]
ROUND_MODE_HALF = "half"
ROUND_MODE_HALF_HALF = "half_half"
ROUND_MODE_SINGLE = "single"
PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 20, "round_mode": ROUND_MODE_SINGLE}]
DEFAULT_SINGLE_ROUNDS = PARAMETERS_CONFIGURATION_LIST[0]["number_of_rounds"]
DEFAULT_HALF_ROUNDS = DEFAULT_SINGLE_ROUNDS * 2
DEFAULT_HALF_HALF_ROUNDS = DEFAULT_HALF_ROUNDS * 2


class ChachaPermutation(Cipher):
    """
    Construct an instance of the ChachaPermutation class.

    This class is used to store compact representations of a permutation, used to generate the corresponding cipher.
    Additionally, one can use this class to implement ChaCha toy ciphers, such as the one described in [DEY2023]_.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `0`); Number of rounds of the permutation. When the value is
            ``0`` the permutation falls back to the default configuration (20 single rounds / 40 half-rounds).
        - ``state_of_components`` -- **list of lists of integer** (default: `None`)
        - ``cipher_family`` -- **string** (default: `chacha_permutation`)
        - ``cipher_type`` -- **string** (default: `permutation`)
        - ``inputs`` -- **list of integer** (default: `None`)
        - ``cipher_inputs_bit_size`` -- **integer** (default: `None`)
        - ``rotations`` -- *list of integer* (default: `[8, 7, 16, 12]`)
        - ``word_size`` -- **integer** (default: `32`)
        - ``start_round`` -- **tuple of strings** (default: (`odd`, `top`)); the second element selects the stage
            the permutation starts on. With ``round_mode="half_half"`` it may be one of ``"top"``
            (alias ``"top_first"``), ``"top_second"``, ``"bottom"`` (alias ``"bottom_first"``) or
            ``"bottom_second"``; otherwise it is ``"top"`` or ``"bottom"``.
        - ``round_mode`` -- **string** (default: `"single"`); selects how ``number_of_rounds`` is interpreted and
            the granularity of the generated CLAASP rounds. The ``"half"`` mode treats the value as a count of
            half-rounds (legacy behaviour), each one made of two independent modular additions. The ``"single"``
            mode treats the value as a count of full rounds, converted internally into their equivalent
            half-rounds (two half-rounds per full round). The ``"half_half"`` mode treats the value as a count of
            quarter-stages -- a single modular addition, XOR and rotation per CLAASP round, i.e. one quarter of a
            full round (four quarter-stages per full round, two per half-round).

    EXAMPLES::

        sage: from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
        sage: chacha = ChachaPermutation(number_of_rounds=2, round_mode="half")
        sage: chacha.number_of_rounds
        2

        sage: quarter = ChachaPermutation(number_of_rounds=4, round_mode="half_half")
        sage: quarter.number_of_rounds
        4
    """

    def __init__(
        self,
        number_of_rounds=0,
        state_of_components=None,
        cipher_family="chacha_permutation",
        cipher_type=PERMUTATION,
        inputs=None,
        cipher_inputs_bit_size=None,
        rotations=[8, 7, 16, 12],
        word_size=32,
        start_round=("odd", "top"),
        round_mode=ROUND_MODE_SINGLE,
    ):
        if round_mode not in {ROUND_MODE_HALF, ROUND_MODE_HALF_HALF, ROUND_MODE_SINGLE}:
            raise ValueError("round_mode must be one of 'half', 'half_half' or 'single'")

        resolved_rounds = self._resolve_rounds(number_of_rounds, round_mode)
        round_granularity = 4 if round_mode == ROUND_MODE_HALF_HALF else 2
        init_latin_dances_cipher(
            self,
            super(),
            INPUT_PLAINTEXT,
            state_of_components,
            resolved_rounds,
            start_round,
            cipher_family,
            cipher_type,
            inputs,
            cipher_inputs_bit_size,
            [COLUMNS, DIAGONALS],
            word_size,
            rotations,
            round_granularity,
        )

    @staticmethod
    def _resolve_rounds(number_of_rounds, round_mode):
        requested_rounds = number_of_rounds
        if requested_rounds == 0:
            requested_rounds = {
                ROUND_MODE_SINGLE: DEFAULT_SINGLE_ROUNDS,
                ROUND_MODE_HALF: DEFAULT_HALF_ROUNDS,
                ROUND_MODE_HALF_HALF: DEFAULT_HALF_HALF_ROUNDS,
            }[round_mode]

        if round_mode == ROUND_MODE_SINGLE:
            return requested_rounds * 2

        return requested_rounds

    def first_quarter_round(self, a, b, c, d, state):
        sub_quarter_round_latin_dances(self, state, a, b, d, -self.rotation_3, "chacha")

    def second_quarter_round(self, a, b, c, d, state):
        sub_quarter_round_latin_dances(self, state, c, d, b, -self.rotation_4, "chacha")

    def third_quarter_round(self, a, b, c, d, state):
        sub_quarter_round_latin_dances(self, state, a, b, d, -self.rotation_1, "chacha")

    def fourth_quarter_round(self, a, b, c, d, state):
        sub_quarter_round_latin_dances(self, state, c, d, b, -self.rotation_2, "chacha")

    def top_half_quarter_round(self, a, b, c, d, state):
        self.first_quarter_round(a, b, c, d, state)
        self.second_quarter_round(a, b, c, d, state)

    def bottom_half_quarter_round(self, a, b, c, d, state):
        self.third_quarter_round(a, b, c, d, state)
        self.fourth_quarter_round(a, b, c, d, state)
