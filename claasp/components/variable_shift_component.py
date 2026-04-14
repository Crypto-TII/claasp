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


import math

from claasp.cipher_modules.models.cp.cp_component_build_result import CpComponentBuildResult
from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.component import Component
from claasp.input import Input
from claasp.name_mappings import WORD_OPERATION


class VariableShift(Component):
    """
    Construct a variable shift component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``parameter`` -- **integer**; operation parameter (for example shift/rotation amount). Negative values are allowed when semantics supports them.

    EXAMPLES::

        sage: from claasp.components.variable_shift_component import VariableShift
        sage: component = VariableShift(0, 0, ['input1', 'input2'], [[0, 1], [0, 1, 2, 3]], 4, 1)
        sage: print(component.id)
        var_shift_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['SHIFT_BY_VARIABLE_AMOUNT', 1]
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
        component_id = f"var_shift_{current_round_number}_{current_round_number_of_components}"
        component_type = WORD_OPERATION
        input_len = sum(map(len, input_bit_positions))
        description = ["SHIFT_BY_VARIABLE_AMOUNT", parameter]
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for SHIFT BY VARIABLE AMOUNT in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        OUTPUT:

        - **tuple** containing:
          * **list** of **string**; output variable identifiers
          * **list** of **string**; SAT clauses in CNF format

        EXAMPLES::

            sage: from claasp.components.variable_shift_component import VariableShift
            sage: variable_shift_component = VariableShift(0, 2, ['plaintext', 'key'], [list(range(4)), list(range(4))], 4, 1)
            sage: output_ids, constraints = variable_shift_component.cms_constraints()
            sage: output_ids
            ['var_shift_0_2_0', 'var_shift_0_2_1', 'var_shift_0_2_2', 'var_shift_0_2_3']
            sage: constraints
            ['-state_0_var_shift_0_2_0 plaintext_0 key_3',
            'state_0_var_shift_0_2_0 -plaintext_0 key_3',
            '-state_0_var_shift_0_2_0 plaintext_1 -key_3',
            'state_0_var_shift_0_2_0 -plaintext_1 -key_3',
            '-state_0_var_shift_0_2_1 plaintext_1 key_3',
            'state_0_var_shift_0_2_1 -plaintext_1 key_3',
            '-state_0_var_shift_0_2_1 plaintext_2 -key_3',
            'state_0_var_shift_0_2_1 -plaintext_2 -key_3',
            '-state_0_var_shift_0_2_2 plaintext_2 key_3',
            'state_0_var_shift_0_2_2 -plaintext_2 key_3',
            '-state_0_var_shift_0_2_2 plaintext_3 -key_3',
            'state_0_var_shift_0_2_2 -plaintext_3 -key_3',
            '-state_0_var_shift_0_2_3 plaintext_3',
            '-state_0_var_shift_0_2_3 -key_3',
            'state_0_var_shift_0_2_3 -plaintext_3 key_3',
            '-var_shift_0_2_0 state_0_var_shift_0_2_0 key_2',
            'var_shift_0_2_0 -state_0_var_shift_0_2_0 key_2',
            '-var_shift_0_2_0 state_0_var_shift_0_2_2 -key_2',
            'var_shift_0_2_0 -state_0_var_shift_0_2_2 -key_2',
            '-var_shift_0_2_1 state_0_var_shift_0_2_1 key_2',
            'var_shift_0_2_1 -state_0_var_shift_0_2_1 key_2',
            '-var_shift_0_2_1 state_0_var_shift_0_2_3 -key_2',
            'var_shift_0_2_1 -state_0_var_shift_0_2_3 -key_2',
            '-var_shift_0_2_2 state_0_var_shift_0_2_2',
            '-var_shift_0_2_2 -key_2',
            'var_shift_0_2_2 -state_0_var_shift_0_2_2 key_2',
            '-var_shift_0_2_3 state_0_var_shift_0_2_3',
            '-var_shift_0_2_3 -key_2',
            'var_shift_0_2_3 -state_0_var_shift_0_2_3 key_2']
        """
        return self.sat_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for SHIFT BY VARIABLE AMOUNT component for CP CIPHER model.

        INPUT:

        - None

        OUTPUT:

        - **tuple** containing:
          * **list** of **string**; MiniZinc variable declarations
          * **list** of **string**; MiniZinc constraints

        EXAMPLES::

            sage: from claasp.components.variable_shift_component import VariableShift
            sage: variable_shift_component = VariableShift(0, 2, ['plaintext', 'key'], [list(range(4)), list(range(4))], 4, 1)
            sage: declarations, constraints = variable_shift_component.cp_constraints()
            sage: declarations
            ['array[0..3] of var 0..1: pre_var_shift_0_2;',
            'var int: shift_amount_var_shift_0_2;']
            sage: constraints
            ['constraint pre_var_shift_0_2[0]=plaintext[0];',
            'constraint pre_var_shift_0_2[1]=plaintext[1];',
            'constraint pre_var_shift_0_2[2]=plaintext[2];',
            'constraint pre_var_shift_0_2[3]=plaintext[3];',
            'constraint bitArrayToInt([key[i]|i in 2..3],shift_amount_var_shift_0_2);',
            'constraint var_shift_0_2=RShift(pre_var_shift_0_2,shift_amount_var_shift_0_2);']
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        numb_of_inp = len(input_id_link)
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        shift_direction = self.description[1]
        bit_for_shift_amount = int(math.log(output_size, 2))
        cp_constraints = []
        cp_declarations = []
        all_inputs = []
        for i in range(numb_of_inp - 1):
            for j in range(len(input_bit_positions[i])):
                all_inputs.append(f"{input_id_link[i]}[{input_bit_positions[i][j]}]")
        cp_declarations.append(f"array[0..{output_size - 1}] of var 0..1: pre_{output_id_link};")
        for i in range(output_size):
            cp_constraints.append(f"constraint pre_{output_id_link}[{i}]={all_inputs[i]};")
        cp_declarations.append(f"var int: shift_amount_{output_id_link};")
        cp_constraints.append(
            f"constraint bitArrayToInt([{input_id_link[numb_of_inp - 1]}[i]|i in "
            f"{input_bit_positions[numb_of_inp - 1][len(input_bit_positions[numb_of_inp - 1]) - bit_for_shift_amount]}"
            f"..{input_bit_positions[numb_of_inp - 1][len(input_bit_positions[numb_of_inp - 1]) - 1]}],"
            f"shift_amount_{output_id_link});"
        )

        if shift_direction == 1:
            cp_constraints.append(
                f"constraint {output_id_link}=RShift(pre_{output_id_link},shift_amount_{output_id_link});"
            )
        else:
            cp_constraints.append(
                f"constraint {output_id_link}=LShift(pre_{output_id_link},shift_amount_{output_id_link});"
            )

        return CpComponentBuildResult(cp_declarations, cp_constraints)

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        """
        Return bit-based vectorized Python code for variable shift operation.

        This method generates Python code for bit-vector implementation of the variable shift component.

        INPUT:

        - ``params`` -- **list**; list of parameter strings representing input components.
        - ``convert_output_to_bytes`` -- **boolean**; if ``True``, output is converted to bytes.

        OUTPUT:

        - **list** of **string**; list of Python code lines for bit-based variable shift operation.

        EXAMPLES::

            sage: from claasp.components.variable_shift_component import VariableShift
            sage: component = VariableShift(0, 0, ['input1', 'input2'], [[0, 1], [0, 1, 2, 3]], 4, 1)
            sage: code = component.get_bit_based_vectorized_python_code(['input1_0_1', 'input2_0_3'], False)
            sage: code
            ['  var_shift_0_0 = bit_vector_SHIFT_BY_VARIABLE_AMOUNT([input1_0_1,input2_0_3 ], 4, 1)']
        """
        return [
            f"  {self.id} = bit_vector_SHIFT_BY_VARIABLE_AMOUNT([{','.join(params)} ], "
            f"{self.output_bit_size}, {self.description[1]})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        """
        Return byte-based vectorized Python code for variable shift operation.

        This method generates Python code for byte-vector implementation of the variable shift component.

        INPUT:

        - ``params`` -- **string**; parameter string representing concatenated input components.

        OUTPUT:

        - **list** of **string**; list of Python code lines for byte-based variable shift operation.

        EXAMPLES::

            sage: from claasp.components.variable_shift_component import VariableShift
            sage: component = VariableShift(0, 0, ['input1', 'input2'], [[0, 1], [0, 1, 2, 3]], 4, 1)
            sage: code = component.get_byte_based_vectorized_python_code('input_concat')
            sage: code
            ['  var_shift_0_0 = byte_vector_SHIFT_BY_VARIABLE_AMOUNT(input_concat, 4, 1)']
        """
        return [
            f"  {self.id} = byte_vector_SHIFT_BY_VARIABLE_AMOUNT({params}, "
            f"{self.output_bit_size}, {self.description[1]})"
        ]

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        """
        Return C code for word-based variable shift operation.

        This method generates C code representing the variable shift component for word-based implementation.

        INPUT:

        - ``verbosity`` -- **boolean**; if ``True``, includes additional print statements for debugging.
        - ``word_size`` -- **integer**; size of word in bits for code generation.
        - ``wordstring_variables`` -- **list**; list to accumulate variable names used in word operations.

        OUTPUT:

        - **list** of **string**; list of C code lines representing the variable shift operation.

        EXAMPLES::

            sage: from claasp.components.variable_shift_component import VariableShift
            sage: component = VariableShift(0, 0, ['input1', 'input2'], [[0, 1], [0, 1, 2, 3]], 4, 1)
            sage: wordstring_variables = []
            sage: code = component.get_word_based_c_code(False, 4, wordstring_variables)
            sage: code
            ['\tinput -> list = (Word[]) {input1 -> list[0], input2 -> list[0]};',
            '\tinput -> string_size = 2;',
            '\tWordString *var_shift_0_0 = RIGHT_SHIFT_BY_VARIABLE_AMOUNT(input);']
        """
        variable_shift_code = []

        self.select_words(variable_shift_code, word_size)
        wordstring_variables.append(self.id)
        direction = "RIGHT" if self.description[1] >= 0 else "LEFT"
        variable_shift_code.append(f"\tWordString *{self.id} = {direction}_{self.description[0]}(input);")

        if verbosity:
            self.print_word_values(variable_shift_code)

        return variable_shift_code

    def get_word_operation_sign(self, sign, solution):
        """
        Update solution dictionary with proper sign information for variable shift.

        This method processes sign information for word operations and updates the solution structure
        to reflect the component's output.

        INPUT:

        - ``sign`` -- **integer**; sign multiplier from parent component (typically 1 or -1).
        - ``solution`` -- **dictionary**; solution dictionary containing component values and metadata.

        OUTPUT:

        - **integer**; updated sign value after applying component sign transformation.

        EXAMPLES::

            sage: from claasp.components.variable_shift_component import VariableShift
            sage: component = VariableShift(0, 0, ['input1', 'input2'], [[0, 1], [0, 1, 2, 3]], 4, 1)
            sage: solution = {
            ....:     'components_values': {
            ....:         'var_shift_0_0_o': {'sign': 1, 'value': 15},
            ....:         'var_shift_0_0_i': {'sign': 1, 'value': 15}
            ....:     }
            ....: }
            sage: result_sign = component.get_word_operation_sign(1, solution)
            sage: result_sign
            1
            sage: 'var_shift_0_0' in solution['components_values']
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

    def minizinc_xor_differential_propagation_constraints(self, model):
        r"""
        Return variables and constraints for the component SHIFT BY VARIABLE AMOUNT for MINIZINC xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        OUTPUT:

        - **tuple** containing:
          * **list** of **string**; MiniZinc variable declarations
          * **list** of **string**; MiniZinc constraints for shift operation

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.variable_shift_cipher import VariableShiftCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: cipher = VariableShiftCipher(bit_size=4, amount_bit_size=4, direction=-1)
            sage: minizinc = MznModel(cipher)
            sage: variable_shift_component = cipher.get_component_from_id('var_shift_0_0')
            sage: var_names, constraints = variable_shift_component.minizinc_xor_differential_propagation_constraints(minizinc)
            sage: var_names
            ['var bool: var_shift_0_0_x0;',
            'var bool: var_shift_0_0_x1;',
            'var bool: var_shift_0_0_x2;',
            'var bool: var_shift_0_0_x3;',
            'var bool: var_shift_0_0_x4;',
            'var bool: var_shift_0_0_x5;',
            'var bool: var_shift_0_0_x6;',
            'var bool: var_shift_0_0_x7;',
            'var bool: var_shift_0_0_y0;',
            'var bool: var_shift_0_0_y1;',
            'var bool: var_shift_0_0_y2;',
            'var bool: var_shift_0_0_y3;']
            sage: constraints
            ['constraint LSHIFT_BY_VARIABLE_AMOUNT(array1d(0..4-1, [var_shift_0_0_x0,var_shift_0_0_x1,var_shift_0_0_x2,var_shift_0_0_x3]), 8*var_shift_0_0_x7+4*var_shift_0_0_x6+2*var_shift_0_0_x5+1*var_shift_0_0_x4)=array1d(0..4-1, [var_shift_0_0_y0,var_shift_0_0_y1,var_shift_0_0_y2,var_shift_0_0_y3]);\n']
        """
        if self.description[0].lower() != "shift_by_variable_amount":
            raise ValueError("component must be bitwise rotation")

        var_names = self._define_var(model.input_postfix, model.output_postfix, model.data_type)
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        input_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        first_subvector_input_vars = input_vars[:noutputs]
        second_subvector_input_vars = input_vars[noutputs:]
        output_vars = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        bin_terms = []

        for i in range(len(second_subvector_input_vars)):
            index_subvector = len(second_subvector_input_vars) - i - 1
            bin_terms.append(f"{2**index_subvector}*{second_subvector_input_vars[index_subvector]}")

        str_shift_amount = "+".join(bin_terms)
        shift_direction = self.description[1]
        mzn_input_array_input = self._create_minizinc_1d_array_from_list(first_subvector_input_vars)
        mzn_input_array_output = self._create_minizinc_1d_array_from_list(output_vars)

        if shift_direction < 0:
            mzn_shift_by_variable_amount_constraints = [
                f"constraint LSHIFT_BY_VARIABLE_AMOUNT({mzn_input_array_input},"
                f" {str_shift_amount})={mzn_input_array_output};\n"
            ]
        else:
            mzn_shift_by_variable_amount_constraints = [
                f"constraint RSHIFT_BY_VARIABLE_AMOUNT({mzn_input_array_input},"
                f" {str_shift_amount})={mzn_input_array_output};\n"
            ]

        return CpComponentBuildResult(var_names, mzn_shift_by_variable_amount_constraints)

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing SHIFT BY VARIABLE AMOUNT for SAT CIPHER model

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        OUTPUT:

        - **tuple** containing:
          * **list** of **string**; output variable identifiers
          * **list** of **string**; SAT clauses in CNF format

        EXAMPLES::

            sage: from claasp.components.variable_shift_component import VariableShift
            sage: variable_shift_component = VariableShift(0, 2, ['plaintext', 'key'], [list(range(4)), list(range(4))], 4, 1)
            sage: output_ids, constraints = variable_shift_component.sat_constraints()
            sage: output_ids
            ['var_shift_0_2_0', 'var_shift_0_2_1', 'var_shift_0_2_2', 'var_shift_0_2_3']
            sage: constraints
            ['-state_0_var_shift_0_2_0 plaintext_0 key_3',
            'state_0_var_shift_0_2_0 -plaintext_0 key_3',
            '-state_0_var_shift_0_2_0 plaintext_1 -key_3',
            'state_0_var_shift_0_2_0 -plaintext_1 -key_3',
            '-state_0_var_shift_0_2_1 plaintext_1 key_3',
            'state_0_var_shift_0_2_1 -plaintext_1 key_3',
            '-state_0_var_shift_0_2_1 plaintext_2 -key_3',
            'state_0_var_shift_0_2_1 -plaintext_2 -key_3',
            '-state_0_var_shift_0_2_2 plaintext_2 key_3',
            'state_0_var_shift_0_2_2 -plaintext_2 key_3',
            '-state_0_var_shift_0_2_2 plaintext_3 -key_3',
            'state_0_var_shift_0_2_2 -plaintext_3 -key_3',
            '-state_0_var_shift_0_2_3 plaintext_3',
            '-state_0_var_shift_0_2_3 -key_3',
            'state_0_var_shift_0_2_3 -plaintext_3 key_3',
            '-var_shift_0_2_0 state_0_var_shift_0_2_0 key_2',
            'var_shift_0_2_0 -state_0_var_shift_0_2_0 key_2',
            '-var_shift_0_2_0 state_0_var_shift_0_2_2 -key_2',
            'var_shift_0_2_0 -state_0_var_shift_0_2_2 -key_2',
            '-var_shift_0_2_1 state_0_var_shift_0_2_1 key_2',
            'var_shift_0_2_1 -state_0_var_shift_0_2_1 key_2',
            '-var_shift_0_2_1 state_0_var_shift_0_2_3 -key_2',
            'var_shift_0_2_1 -state_0_var_shift_0_2_3 -key_2',
            '-var_shift_0_2_2 state_0_var_shift_0_2_2',
            '-var_shift_0_2_2 -key_2',
            'var_shift_0_2_2 -state_0_var_shift_0_2_2 key_2',
            '-var_shift_0_2_3 state_0_var_shift_0_2_3',
            '-var_shift_0_2_3 -key_2',
            'var_shift_0_2_3 -state_0_var_shift_0_2_3 key_2']  
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        input_ids = input_bit_ids[:output_bit_len]
        shift_ids = input_bit_ids[output_bit_len:]
        number_of_states = int(math.log2(output_bit_len)) - 1
        states = [[f"state_{i}_{output_bit_ids[j]}" for j in range(output_bit_len)] for i in range(number_of_states)]
        constraints = []
        for j in range(output_bit_len - 1):
            constraints.extend(
                sat_utils.cnf_vshift_id(states[0][j], input_ids[j], input_ids[j + 1], shift_ids[output_bit_len - 1])
            )
        constraints.extend(
            sat_utils.cnf_vshift_false(
                states[0][output_bit_len - 1], input_ids[output_bit_len - 1], shift_ids[output_bit_len - 1]
            )
        )
        for i in range(1, number_of_states):
            for j in range(output_bit_len - 2**i):
                constraints.extend(
                    sat_utils.cnf_vshift_id(
                        states[i][j], states[i - 1][j], states[i - 1][j + 2**i], shift_ids[output_bit_len - 1 - i]
                    )
                )
            for j in range(output_bit_len - 2**i, output_bit_len):
                constraints.extend(
                    sat_utils.cnf_vshift_false(states[i][j], states[i - 1][j], shift_ids[output_bit_len - 1 - i])
                )
        for j in range(output_bit_len - 2**number_of_states):
            constraints.extend(
                sat_utils.cnf_vshift_id(
                    output_bit_ids[j],
                    states[number_of_states - 1][j],
                    states[number_of_states - 1][j + 2**number_of_states],
                    shift_ids[output_bit_len - 1 - number_of_states],
                )
            )
        for j in range(output_bit_len - 2**number_of_states, output_bit_len):
            constraints.extend(
                sat_utils.cnf_vshift_false(
                    output_bit_ids[j], states[number_of_states - 1][j], shift_ids[output_bit_len - 1 - number_of_states]
                )
            )

        return output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing SHIFT BY VARIABLE AMOUNT for SMT CIPHER model

        INPUT:

        - None

        OUTPUT:

        - **tuple** containing:
          * **list** of **string**; state and output variable identifiers
          * **list** of **string**; SMT assertions in SMT-LIB format

        EXAMPLES::

            sage: from claasp.components.variable_shift_component import VariableShift
            sage: variable_shift_component = VariableShift(0, 2, ['plaintext', 'key'], [list(range(4)), list(range(4))], 4, 1)
            sage: variables, constraints = variable_shift_component.smt_constraints()
            sage: variables
            ['state_0_var_shift_0_2_0',
            'state_0_var_shift_0_2_1',
            'state_0_var_shift_0_2_2',
            'state_0_var_shift_0_2_3',
            'var_shift_0_2_0',
            'var_shift_0_2_1',
            'var_shift_0_2_2',
            'var_shift_0_2_3']
            sage: constraints
            ['(assert (ite key_3 (= state_0_var_shift_0_2_0 plaintext_1) (= state_0_var_shift_0_2_0 plaintext_0)))',
            '(assert (ite key_3 (= state_0_var_shift_0_2_1 plaintext_2) (= state_0_var_shift_0_2_1 plaintext_1)))',
            '(assert (ite key_3 (= state_0_var_shift_0_2_2 plaintext_3) (= state_0_var_shift_0_2_2 plaintext_2)))',
            '(assert (ite key_3 (not state_0_var_shift_0_2_3) (= state_0_var_shift_0_2_3 plaintext_3)))',
            '(assert (ite key_2 (= var_shift_0_2_0 state_0_var_shift_0_2_2) (= var_shift_0_2_0 state_0_var_shift_0_2_0)))',
            '(assert (ite key_2 (= var_shift_0_2_1 state_0_var_shift_0_2_3) (= var_shift_0_2_1 state_0_var_shift_0_2_1)))',
            '(assert (ite key_2 (not var_shift_0_2_2) (= var_shift_0_2_2 state_0_var_shift_0_2_2)))',
            '(assert (ite key_2 (not var_shift_0_2_3) (= var_shift_0_2_3 state_0_var_shift_0_2_3)))']
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        input_ids = input_bit_ids[:output_bit_len]
        shift_ids = input_bit_ids[output_bit_len:]
        states = []
        number_of_states = int(math.log2(output_bit_len)) - 1
        for i in range(number_of_states):
            states.append([f"state_{i}_{output_bit_ids[j]}" for j in range(output_bit_len)])
        constraints = []
        if len(states) <= 0:
            raise ValueError("states must not be empty")

        # first shift
        for j in range(output_bit_len - 1):
            consequent = smt_utils.smt_equivalent((states[0][j], input_ids[j + 1]))
            alternative = smt_utils.smt_equivalent((states[0][j], input_ids[j]))
            shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1], consequent, alternative)
            constraints.append(smt_utils.smt_assert(shift))
        consequent = smt_utils.smt_not(states[0][output_bit_len - 1])
        alternative = smt_utils.smt_equivalent((states[0][output_bit_len - 1], input_ids[output_bit_len - 1]))
        shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1], consequent, alternative)
        constraints.append(smt_utils.smt_assert(shift))

        # intermediate shifts
        for i in range(1, number_of_states):
            for j in range(output_bit_len - 2**i):
                consequent = smt_utils.smt_equivalent((states[i][j], states[i - 1][j + 2**i]))
                alternative = smt_utils.smt_equivalent((states[i][j], states[i - 1][j]))
                shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1 - i], consequent, alternative)
                constraints.append(smt_utils.smt_assert(shift))
            for j in range(output_bit_len - 2**i, output_bit_len):
                consequent = smt_utils.smt_not(states[i][j])
                alternative = smt_utils.smt_equivalent((states[i][j], states[i - 1][j]))
                shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1 - i], consequent, alternative)
                constraints.append(smt_utils.smt_assert(shift))

        # last shift
        for j in range(output_bit_len - 2**number_of_states):
            consequent = smt_utils.smt_equivalent(
                (output_bit_ids[j], states[number_of_states - 1][j + 2**number_of_states])
            )
            alternative = smt_utils.smt_equivalent((output_bit_ids[j], states[number_of_states - 1][j]))
            shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1 - number_of_states], consequent, alternative)
            constraints.append(smt_utils.smt_assert(shift))
        for j in range(output_bit_len - 2**number_of_states, output_bit_len):
            consequent = smt_utils.smt_not(output_bit_ids[j])
            alternative = smt_utils.smt_equivalent((output_bit_ids[j], states[number_of_states - 1][j]))
            shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1 - number_of_states], consequent, alternative)
            constraints.append(smt_utils.smt_assert(shift))

        # create state variables list
        state_bit_ids = [bit_id for state in states for bit_id in state]

        return state_bit_ids + output_bit_ids, constraints
