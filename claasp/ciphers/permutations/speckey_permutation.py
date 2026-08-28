# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
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
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION
from claasp.utils.utils import coerce_exact_int, get_inputs_parameter


_WORD_SIZE = 16
_NUMBER_OF_WORDS = 2
_ROTATION_RIGHT = 7
_ROTATION_LEFT = -2

PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 1}]


class SpeckeyPermutation(Cipher):
    """
    Construct an instance of the SpeckeyPermutation class.

    Speckey is a 32-bit ARX permutation based on one round of Speck-32,
    using two 16-bit words, as described in [DPUVGB2016]_.

    INPUT:

    - ``number_of_rounds`` -- **integer** (default: `1`); number of rounds of the permutation

    EXAMPLES::

        sage: from claasp.ciphers.permutations.speckey_permutation import SpeckeyPermutation
        sage: speckey = SpeckeyPermutation()
        sage: speckey.evaluate([0], verbosity=False)
        0

        sage: reduced = SpeckeyPermutation(number_of_rounds=3)
        sage: reduced.evaluate([0x00112233], verbosity=False) == 0x0EDF0F3F
        True
    """

    def __init__(self, number_of_rounds=1):
        try:
            number_of_rounds = coerce_exact_int(number_of_rounds, "number_of_rounds")
        except ValueError:
            raise ValueError("number_of_rounds must be > 0")
        if number_of_rounds <= 0:
            raise ValueError("number_of_rounds must be > 0")

        self.word_size = _WORD_SIZE
        self.number_of_words = _NUMBER_OF_WORDS
        self.state_bit_size = self.word_size * self.number_of_words

        super().__init__(
            family_name="speckey_permutation",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        state = []
        for word_index in range(self.number_of_words):
            bit_positions = [
                bit + word_index * self.word_size
                for bit in range(self.word_size)
            ]
            state.append(
                ComponentState([INPUT_PLAINTEXT], [bit_positions])
            )

        for round_number in range(number_of_rounds):
            self.add_round()
            state = self.round_function(state)

            inputs_id, inputs_pos = get_inputs_parameter(state)
            if round_number == number_of_rounds - 1:
                self.add_cipher_output_component(
                    inputs_id,
                    inputs_pos,
                    self.state_bit_size,
                )
            else:
                self.add_round_output_component(
                    inputs_id,
                    inputs_pos,
                    self.state_bit_size,
                )

    def _state_from_current_component(self):
        return ComponentState(
            [self.get_current_component_id()],
            [list(range(self.word_size))],
        )

    def _modadd_words(self, left, right):
        inputs_id, inputs_pos = get_inputs_parameter([left, right])
        self.add_modadd_component(
            inputs_id,
            inputs_pos,
            self.word_size,
        )

        return self._state_from_current_component()

    def _xor_words(self, left, right):
        inputs_id, inputs_pos = get_inputs_parameter([left, right])
        self.add_xor_component(
            inputs_id,
            inputs_pos,
            self.word_size,
        )

        return self._state_from_current_component()

    def _rotate_word(self, state, amount):
        self.add_rotate_component(
            state.id,
            state.input_bit_positions,
            self.word_size,
            amount,
        )

        return self._state_from_current_component()

    def round_function(self, state):
        x, y = state

        x = self._rotate_word(x, _ROTATION_RIGHT)
        x = self._modadd_words(x, y)
        y = self._rotate_word(y, _ROTATION_LEFT)
        y = self._xor_words(y, x)

        return [x, y]
