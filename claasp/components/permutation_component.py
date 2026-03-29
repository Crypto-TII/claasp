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


from claasp.components.linear_layer_component import LinearLayer


class Permutation(LinearLayer):
    """
    Construct a permutation component.


    INPUT:

    - Parameters follow this class constructor (``__init__``) signature.
    - Required parameters should not be ``None``.
    - ``0`` is valid for round/component indices and numeric parameters when semantically meaningful.
    - For list parameters, pass Python lists; ``[]`` is valid only when explicitly supported by the component semantics.
    EXAMPLES::

        sage: from claasp.components.permutation_component import Permutation
        sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
        sage: print(component.id)
        linear_layer_0_0
        sage: print(component.type)
        linear_layer
        sage: print(component.description[0])
        [0, 1, 0, 0]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        permutation_description,
    ):
        matrix = []
        for i in range(output_bit_size):
            row = [0] * output_bit_size
            row[permutation_description[i]] = 1
            matrix.append(row)
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            matrix,
        )
