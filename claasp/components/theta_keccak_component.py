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


from claasp.cipher_modules.generic_functions import THETA_KECCAK
from claasp.component import linear_layer_to_binary_matrix
from claasp.components.linear_layer_component import LinearLayer
from claasp.input import Input


class ThetaKeccak(LinearLayer):
    """
    Construct a Theta-Keccak component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.

    EXAMPLES::

        sage: from claasp.components.theta_keccak_component import ThetaKeccak
        sage: component = ThetaKeccak(0, 0, ['input'], [[i for i in range(25)]], 25)
        sage: print(component.id)
        theta_keccak_0_0
        sage: print(component.type)
        linear_layer
        sage: print(component.input_bit_size)
        25
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
    ):
        binary_matrix = linear_layer_to_binary_matrix(THETA_KECCAK, output_bit_size, output_bit_size, [])
        description = list(binary_matrix.transpose())
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            description,
        )
        self._id = f"theta_keccak_{current_round_number}_{current_round_number_of_components}"
        self._input = Input(output_bit_size, input_id_links, input_bit_positions)
