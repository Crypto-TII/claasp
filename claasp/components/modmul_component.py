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


from claasp.components.modular_component import Modular


class MODMUL(Modular):
    """
    Construct a modular multiplication component.


    INPUT:

    - Parameters follow this class constructor (``__init__``) signature.
    - Required parameters should not be ``None``.
    - ``0`` is valid for round/component indices and numeric parameters when semantically meaningful.
    - For list parameters, pass Python lists; ``[]`` is valid only when explicitly supported by the component semantics.
    EXAMPLES::

        sage: from claasp.components.modmul_component import MODMUL
        sage: component = MODMUL(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
        sage: print(component.id)
        modmul_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['MODMUL', 2, 2]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        modulus,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            "modmul",
            modulus,
        )

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [
            f"  {self.id} = bit_vector_MODMUL([{','.join(params)} ], {self.description[1]}, {self.output_bit_size})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_MODMUL({params})"]
