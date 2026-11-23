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


from claasp.component import Component
from claasp.input import Input
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

    def cp_constraints(self):
        """Return exact MiniZinc bit-value constraints for a variable rotation.

        The first output-width input bits form the data word; the remaining
        bits encode an unsigned rotation amount, most significant bit first.
        Positive direction parameters rotate right; negative ones rotate left.
        The amount is reduced modulo the word width, as in the evaluator.

        INPUT: none. The component wiring supplies data and amount bits.

        OUTPUT: a pair of lists: auxiliary declarations and exact equations.
        These are value constraints, not XOR-differential probability weights.
        See Rivest, *The RC5 Encryption Algorithm*, FSE 1994,
        https://doi.org/10.1007/3-540-60590-8_7.

        EXAMPLES::

            sage: from claasp.components.variable_rotate_component import VariableRotate
            sage: component = VariableRotate(0, 0, ['word', 'amount'], [[0, 1, 2, 3], [0, 1]], 4, -1)
            sage: declarations, equations = component.cp_constraints()
            sage: len(declarations), len(equations)
            (2, 5)
        """
        width = self.output_bit_size
        inputs = [
            f"{name}[{bit}]"
            for name, positions in zip(self.input_id_links, self.input_bit_positions)
            for bit in positions
        ]
        if width < 1 or len(inputs) <= width:
            raise ValueError("Variable rotation requires a data word and an amount")
        word, amount = inputs[:width], inputs[width:]
        amount_expression = " + ".join(
            f"{pow(2, len(amount) - i - 1, width)}*{bit}" for i, bit in enumerate(amount)
        )
        declarations = [
            f"array[0..{width - 1}] of var 0..1: {self.id}_input = array1d(0..{width - 1}, [{', '.join(word)}]);",
            f"var 0..{width - 1}: {self.id}_amount;",
        ]
        constraints = [f"constraint {self.id}_amount = ({amount_expression}) mod {width};"]
        multiplier = int(self.description[1]) % width
        constraints.extend(
            f"constraint {self.id}[{i}] = {self.id}_input[({i} - {multiplier}*{self.id}_amount + {width * width}) mod {width}];"
            for i in range(width)
        )
        return declarations, constraints

    def cp_xor_differential_propagation_constraints(self, model=None):
        """Refuse differential weighting until a variable-rotation model exists.

        Exact values are supported by :meth:`cp_constraints`. Rotating an XOR
        difference by its amount difference would be incorrect. Use an exact
        full-middle boomerang search for value feasibility without arm scores.

        INPUT: optional differential model, unused.

        OUTPUT: raises ``NotImplementedError``; no approximate weight is supplied.

        EXAMPLES::

            sage: from claasp.components.variable_rotate_component import VariableRotate
            sage: component = VariableRotate(0, 0, ['word', 'amount'], [[0, 1, 2, 3], [0, 1]], 4, -1)
            sage: component.cp_xor_differential_propagation_constraints()
            Traceback (most recent call last):
            ...
            NotImplementedError: Variable-rotation differential weights are not implemented; use exact full-middle value feasibility
        """
        raise NotImplementedError(
            "Variable-rotation differential weights are not implemented; use exact full-middle value feasibility"
        )

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
            sage: code
            ['\tinput -> list = (Word[]) {input -> list[0]};',
            '\tinput -> string_size = 1;',
            '\tWordString *var_rot_0_0 = RIGHT_ROTATE_BY_VARIABLE_AMOUNT(input);']
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


    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        """Return code evaluating the exact variable rotation on bit matrices.

        INPUT: ``params`` is a list of selected-input code strings;
        ``convert_output_to_bytes`` is the standard generator flag (conversion
        remains the caller's responsibility).

        OUTPUT: a one-element list of Python source lines.

        EXAMPLES::

            sage: from claasp.components.variable_rotate_component import VariableRotate
            sage: c = VariableRotate(0, 0, ['x', 's'], [[0, 1], [0]], 2, 1)
            sage: c.get_bit_based_vectorized_python_code(['x', 's'], False)
            ['  var_rot_0_0 = bit_vector_rotate_by_variable_amount([x,s], 2, 1)']
        """
        return [f"  {self.id} = bit_vector_rotate_by_variable_amount([{','.join(params)}], {self.output_bit_size}, {self.description[1]})"]

    def get_byte_based_vectorized_python_code(self, params):
        """Return code evaluating the exact rotation on packed byte matrices.

        INPUT: ``params`` is the selected-input expression produced by the
        standard byte-vector formatter.

        OUTPUT: a one-element list of Python source lines, including the actual
        amount width so that partial-byte padding cannot become amount bits.

        EXAMPLES::

            sage: from claasp.components.variable_rotate_component import VariableRotate
            sage: c = VariableRotate(0, 0, ['x', 's'], [[0, 1], [0]], 2, -1)
            sage: c.get_byte_based_vectorized_python_code('selected')
            ['  var_rot_0_0 = byte_vector_rotate_by_variable_amount(selected, 2, -1, 1)']
        """
        return [f"  {self.id} = byte_vector_rotate_by_variable_amount({params}, {self.output_bit_size}, {self.description[1]}, {self.input_bit_size - self.output_bit_size})"]
