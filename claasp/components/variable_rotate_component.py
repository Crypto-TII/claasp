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

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``parameter`` -- **integer**; operation parameter (for example shift/rotation amount). Negative values are allowed when semantics supports them.

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
        """
        Return C code for word-based variable rotation operation.

        This method generates C code representing the variable rotate component for word-based implementation.

        INPUT:

        - ``verbosity`` -- **boolean**; if ``True``, includes additional print statements for debugging.
        - ``word_size`` -- **integer**; size of word in bits for code generation.
        - ``wordstring_variables`` -- **list**; list to accumulate variable names used in word operations.

        OUTPUT:

        - **list** of **string**; list of C code lines representing the variable rotation operation.

        EXAMPLES::

            sage: from claasp.components.variable_rotate_component import VariableRotate
            sage: component = VariableRotate(0, 0, ['input'], [[0, 1, 2, 3]], 4, 1)
            sage: wordstring_variables = []
            sage: code = component.get_word_based_c_code(False, 4, wordstring_variables)
            sage: len(code) > 0
            True
            sage: 'var_rot_0_0' in wordstring_variables
            True
        """
        variable_rotate_code = []

        self.select_words(variable_rotate_code, word_size)
        wordstring_variables.append(self.id)
        direction = "RIGHT" if self.description[1] >= 0 else "LEFT"
        variable_rotate_code.append(f"\tWordString *{self.id} = {direction}_{self.description[0]}(input);")

        if verbosity:
            self.print_word_values(variable_rotate_code)

        return variable_rotate_code

    def get_word_operation_sign(self, sign, solution):
        """
        Update solution dictionary with proper sign information for variable rotation.

        This method processes sign information for word operations and updates the solution structure
        to reflect the component's output.

        INPUT:

        - ``sign`` -- **integer**; sign multiplier from parent component (typically 1 or -1).
        - ``solution`` -- **dictionary**; solution dictionary containing component values and metadata.

        OUTPUT:

        - **integer**; updated sign value after applying component sign transformation.

        EXAMPLES::

            sage: from claasp.components.variable_rotate_component import VariableRotate
            sage: component = VariableRotate(0, 0, ['input'], [[0, 1, 2, 3]], 4, 1)
            sage: solution = {
            ....:     'components_values': {
            ....:         'var_rot_0_0_o': {'sign': 1, 'value': 15},
            ....:         'var_rot_0_0_i': {'sign': 1, 'value': 15}
            ....:     }
            ....: }
            sage: result_sign = component.get_word_operation_sign(1, solution)
            sage: result_sign
            1
            sage: 'var_rot_0_0' in solution['components_values']
            True
        """
        output_id_link = self.id
        component_sign = 1
        sign = sign * component_sign
        solution["components_values"][f"{output_id_link}_o"]["sign"] = component_sign
        solution["components_values"][output_id_link] = solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_i"]

        return sign
