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


from claasp.components.permutation_component import Permutation


class WordPermutation(Permutation):
    """
    Construct a word permutation component.

    A permutation component that models a word-wise permutation as simple bit equalities.
    The permutation description follows the CLAASP convention where each entry gives the
    destination position of the corresponding source word: ``permutation_description[i]``
    is the destination word index for source word ``i``, and the list has
    ``output_bit_size // word_size`` entries.

    All constraint generation (algebraic, SAT, SMT, CP, MILP) and code generation is
    inherited unchanged from :py:class:`~claasp.components.permutation_component.Permutation`,
    which already supports ``word_size > 1`` generically.

    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. Must be divisible by ``word_size``.
    - ``permutation_description`` -- **list**; permutation mapping from source word position to
      destination word position. ``permutation_description[i]`` is the destination word index for
      source word ``i``, and the list has ``output_bit_size // word_size`` entries.
    - ``word_size`` -- **integer**; number of bits per word.

    EXAMPLES::

        sage: from claasp.components.word_permutation_component import WordPermutation
        sage: component = WordPermutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 0], 2)
        sage: print(component.id)
        permutation_0_0
        sage: print(component.type)
        permutation
        sage: print(component.description)
        [[1, 0], 2]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        permutation_description,
        word_size,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            permutation_description,
            word_size,
        )
