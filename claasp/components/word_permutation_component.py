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


from claasp.components.mix_column_component import MixColumn


class WordPermutation(MixColumn):
    """
    Construct a word permutation component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``permutation_description`` -- **list**; permutation mapping description.
    - ``word_size`` -- **integer**; word size used by the permutation construction.

    EXAMPLES::

        sage: from claasp.components.word_permutation_component import WordPermutation
        sage: component = WordPermutation(0, 0, ['input'], [[0, 1, 2, 3]], 0, [1, 0], 2)
        sage: print(component.id)
        mix_column_0_0
        sage: print(component.type)
        mix_column
        sage: print(component.description[2])
        2
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
        matrix = []
        for i in range(len(permutation_description)):
            row = [0] * len(permutation_description)
            row[permutation_description[i]] = 1
            matrix.append(row)
        description = [matrix, 0, word_size]
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            description,
        )
