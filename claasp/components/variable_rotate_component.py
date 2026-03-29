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


from claasp.input import Input
from claasp.component import Component
from claasp.name_mappings import WORD_OPERATION


class VariableRotate(Component):
    """
    Construct a variable rotate component.


    INPUT:

    - Parameters follow this class constructor (``__init__``) signature.
    - Required parameters should not be ``None``.
    - ``0`` is valid for round/component indices and numeric parameters when semantically meaningful.
    - For list parameters, pass Python lists; ``[]`` is valid only when explicitly supported by the component semantics.
    EXAMPLES::

        sage: from claasp.components.variable_rotate_component import VariableRotate
        sage: component = VariableRotate(0, 0, ['input'], [[0, 1, 2, 3]], 4, -1)
        sage: print(component.id)
        var_rot_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['ROTATE_BY_VARIABLE_AMOUNT', -1]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        parameter,
    ):
        component_id = f"var_rot_{current_round_number}_{current_round_number_of_components}"
        component_type = WORD_OPERATION
        input_len = sum(map(len, input_bit_positions))
        description = ["ROTATE_BY_VARIABLE_AMOUNT", parameter]
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        variable_rotate_code = []

        self.select_words(variable_rotate_code, word_size)
        wordstring_variables.append(self.id)
        direction = "RIGHT" if self.description[1] >= 0 else "LEFT"
        variable_rotate_code.append(f"\tWordString *{self.id} = {direction}_{self.description[0]}(input);")

        if verbosity:
            self.print_word_values(variable_rotate_code)

        return variable_rotate_code

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        component_sign = 1
        sign = sign * component_sign
        solution["components_values"][f"{output_id_link}_o"]["sign"] = component_sign
        solution["components_values"][output_id_link] = solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_i"]

        return sign
