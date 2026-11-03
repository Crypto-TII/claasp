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

from claasp.DTOs.component_state import ComponentState
from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION
from claasp.utils.utils import coerce_exact_int, get_inputs_parameter

_DEFAULT_ROTATIONS = (-5, -8, -13, -7, -16)
_NUMBER_OF_WORDS = 4
PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 12, "word_size": 32}]


def _coerce_half_round_multiple(value, parameter_name):
    """Accept a positive multiple of 0.5 and return the corresponding number of *half-rounds*."""
    if isinstance(value, bool):
        raise ValueError(f"{parameter_name} must be a positive multiple of 0.5")
    try:
        as_float = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{parameter_name} must be a positive multiple of 0.5")
    halves = as_float * 2.0
    nearest = round(halves)
    if abs(halves - nearest) > 1e-9:
        raise ValueError(f"{parameter_name} must be a positive multiple of 0.5")
    halves = int(nearest)
    if halves <= 0:
        raise ValueError(f"{parameter_name} must be a positive multiple of 0.5")

    return halves


class ChaskeyPiPermutation(Cipher):
    """
    Construct an instance of the ChaskeyPiPermutation class.

    This class models the Chaskey-Pi permutation over 4 words as described in [Mouha2015]_.

    Like the ChaCha and Salsa CLAASP permutations, the round is built at *half-round* granularity:
    ``number_of_rounds`` counts full rounds and may be any positive multiple of ``0.5`` (e.g. ``7.5``).
    Each CLAASP round is one half-round, a balanced sub-round of 7 components (2 modular additions,
    2 XORs, 3 rotations) whose two modular additions are independent of each other:

    - top half (``start_round=("top",)``): ``v0+=v1; v1<<<5; v1^=v0; v0<<<16; v2+=v3; v3<<<8; v3^=v2``
    - bottom half (``start_round=("bottom",)``): ``v0+=v3; v3<<<13; v3^=v0; v2+=v1; v1<<<7; v1^=v2; v2<<<16``

    A full round is the top half followed by the bottom half, so ``cipher.number_of_rounds`` is twice the
    number of full rounds requested.

    INPUT:

    - ``number_of_rounds`` -- **integer or half-integer** (default: `12`); number of full rounds, any positive
      multiple of 0.5
    - ``word_size`` -- **integer** (default: `32`); size in bits of each state word
    - ``rotations`` -- **tuple of 5 integers** (default: ``(-5, -8, -13, -7, -16)``)
    - ``start_round`` -- **tuple of strings** (default: ``("top",)``); ``("top",)`` or ``("bottom",)``, the half-round
      the permutation starts with

    EXAMPLES::

        sage: from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation
        sage: chaskeypi = ChaskeyPiPermutation()
        sage: chaskeypi.number_of_rounds
        24

        sage: reduced = ChaskeyPiPermutation(number_of_rounds=4, word_size=16)
        sage: reduced.id
        'chaskeypi_permutation_p64_o64_r8'

        sage: half = ChaskeyPiPermutation(number_of_rounds=7.5)
        sage: half.number_of_rounds
        15

        sage: bottom_first = ChaskeyPiPermutation(number_of_rounds=0.5, start_round=("bottom",))
        sage: bottom_first.number_of_rounds
        1
    """

    def __init__(self, number_of_rounds=12, word_size=32, rotations=_DEFAULT_ROTATIONS, start_round=("top",)):
        try:
            word_size = coerce_exact_int(word_size, "word_size")
        except ValueError:
            raise ValueError("word_size must be a positive integer")
        if word_size <= 0:
            raise ValueError("word_size must be a positive integer")

        # number_of_rounds counts full rounds and may be a multiple of 0.5
        number_of_half_rounds = _coerce_half_round_multiple(number_of_rounds, "number_of_rounds")

        if len(rotations) != 5:
            raise ValueError("rotations must contain exactly 5 values")
        try:
            rotations = tuple(coerce_exact_int(rotation, "rotation") for rotation in rotations)
        except ValueError:
            raise ValueError("rotations values must be integers")

        if not (
            isinstance(start_round, (tuple, list))
            and len(start_round) >= 1
            and str(start_round[0]).lower() in ("top", "bottom")
        ):
            raise ValueError('start_round must be ("top",) or ("bottom",)')
        start_bottom = 1 if str(start_round[0]).lower() == "bottom" else 0

        self.word_size = word_size
        self.number_of_words = _NUMBER_OF_WORDS
        self.rotations = rotations
        self.state_bit_size = self.word_size * self.number_of_words

        super().__init__(
            family_name="chaskeypi_permutation",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.state_bit_size],
            cipher_output_bit_size=self.state_bit_size,
        )

        state = []
        for word_index in range(self.number_of_words):
            bit_positions = [bit + word_index * self.word_size for bit in range(self.word_size)]
            state.append(ComponentState([INPUT_PLAINTEXT], [bit_positions]))

        # each CLAASP round is one balanced half-round (7 components)
        for half_index in range(number_of_half_rounds):
            self.add_round()
            if (half_index + start_bottom) % 2 == 0:
                state = self.round_function_top_half(state)
            else:
                state = self.round_function_bottom_half(state)

            inputs_id, inputs_pos = get_inputs_parameter(state)
            if half_index == number_of_half_rounds - 1:
                self.add_cipher_output_component(inputs_id, inputs_pos, self.state_bit_size)
            else:
                self.add_round_output_component(inputs_id, inputs_pos, self.state_bit_size)

    def _state_from_current_component(self):
        return ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

    def _modadd_words(self, left, right):
        inputs_id, inputs_pos = get_inputs_parameter([left, right])
        self.add_modadd_component(inputs_id, inputs_pos, self.word_size)

        return self._state_from_current_component()

    def _xor_words(self, left, right):
        inputs_id, inputs_pos = get_inputs_parameter([left, right])
        self.add_xor_component(inputs_id, inputs_pos, self.word_size)

        return self._state_from_current_component()

    def _rotate_word(self, state, amount):
        self.add_rotate_component(state.id, state.input_bit_positions, self.word_size, amount)

        return self._state_from_current_component()

    def round_function_top_half(self, state):
        """First balanced half-round: the v0/v1 and v2/v3 ARX steps (7 components)."""
        v0, v1, v2, v3 = state

        # v[0] += v[1]; v[1] = ROTL(v[1], 5); v[1] ^= v[0]; v[0] = ROTL(v[0], 16)
        v0 = self._modadd_words(v0, v1)
        v1 = self._rotate_word(v1, self.rotations[0])
        v1 = self._xor_words(v1, v0)
        v0 = self._rotate_word(v0, self.rotations[4])

        # v[2] += v[3]; v[3] = ROTL(v[3], 8); v[3] ^= v[2]
        v2 = self._modadd_words(v2, v3)
        v3 = self._rotate_word(v3, self.rotations[1])
        v3 = self._xor_words(v3, v2)

        return [v0, v1, v2, v3]

    def round_function_bottom_half(self, state):
        """Second balanced half-round: the v0/v3 and v2/v1 ARX steps (7 components)."""
        v0, v1, v2, v3 = state

        # v[0] += v[3]; v[3] = ROTL(v[3], 13); v[3] ^= v[0]
        v0 = self._modadd_words(v0, v3)
        v3 = self._rotate_word(v3, self.rotations[2])
        v3 = self._xor_words(v3, v0)

        # v[2] += v[1]; v[1] = ROTL(v[1], 7); v[1] ^= v[2]; v[2] = ROTL(v[2], 16)
        v2 = self._modadd_words(v2, v1)
        v1 = self._rotate_word(v1, self.rotations[3])
        v1 = self._xor_words(v1, v2)
        v2 = self._rotate_word(v2, self.rotations[4])

        return [v0, v1, v2, v3]

    def round_function(self, state):
        """A full round: the top half followed by the bottom half."""
        return self.round_function_bottom_half(self.round_function_top_half(state))
