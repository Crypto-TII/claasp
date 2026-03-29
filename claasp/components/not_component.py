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
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.sat.utils import constants, utils as sat_utils
from claasp.name_mappings import WORD_OPERATION


class NOT(Component):
    """
    Construct a NOT component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.

    EXAMPLES::

        sage: from claasp.components.not_component import NOT
        sage: component = NOT(0, 0, ['input'], [[0, 1]], 2)
        sage: print(component.id)
        not_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['NOT', 0]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
    ):
        component_id = f"not_{current_round_number}_{current_round_number_of_components}"
        component_type = WORD_OPERATION
        description = ["NOT", 0]
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for bitwise NOT.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = NotCipher(bit_size=8)
            sage: algebraic = AlgebraicModel(cipher)
            sage: not_component = cipher.component_from(0, 0)
            sage: algebraic_polynomials = not_component.algebraic_polynomials(algebraic)
            sage: len(algebraic_polynomials)
            8
            sage: str(algebraic_polynomials[0]).endswith('+ 1')
            True
        """
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        input_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]
        output_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]
        ring_R = model.ring()
        x = list(map(ring_R, input_vars))
        y = list(map(ring_R, output_vars))

        polynomials = [y[i] + x[i] + 1 for i in range(noutputs)]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for NOT operation in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(32))], 32)
                        sage: output_ids, constraints = not_component.cms_constraints()
                        sage: output_ids[0]
                        'not_0_0_0'
                        sage: len(constraints) == 64
                        True
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model):
        return self.sat_xor_differential_propagation_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model):
        return self.sat_xor_linear_mask_propagation_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for NOT component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.not_component import NOT
            sage: not_component = NOT(0, 0, ['input0'], [list(range(32))], 32)
            sage: declarations, constraints = not_component.cp_constraints()
            sage: declarations
            []
            sage: constraints[0]
            'constraint not_0_0[0] = (input0[0] + 1) mod 2;'
        """
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_constraints = [f"constraint {self.id}[{i}] = ({input_} + 1) mod 2;" for i, input_ in enumerate(all_inputs)]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_constraints(self):
        """
        Return lists of declarations and constraints for NOT for CP deterministic truncated xor differential model.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.components.not_component import NOT
            sage: not_component = NOT(0, 0, ['input0'], [list(range(32))], 32)
            sage: declarations, constraints = not_component.cp_deterministic_truncated_xor_differential_constraints()
            sage: declarations
            []
            sage: constraints[0]
            'constraint not_0_0[0] = input0[0];'
        """
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_constraints = [f"constraint {self.id}[{i}] = {input_};" for i, input_ in enumerate(all_inputs)]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_trail_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        cp_declarations = []
        all_inputs_value = []
        all_inputs_active = []
        word_size = model.word_size
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs_value.extend(
                [
                    f"{id_link}_value[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
            all_inputs_active.extend(
                [
                    f"{id_link}_active[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
        input_len = len(all_inputs_value)
        cp_constraints = []
        for i in range(input_len):
            cp_constraints.append(f"constraint {self.id}_active[{i}] = {all_inputs_active[i]};")
            cp_constraints.append(
                f"if {all_inputs_value[i]} < 0 then {self.id}_value[{i}] = {all_inputs_value[i]} "
                f"else {self.id}_value[{i}] = {2**word_size - 1} - {all_inputs_value[i]}"
            )

        return cp_declarations, cp_constraints

    def cp_xor_differential_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for NOT component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.not_component import NOT
            sage: class DummyModel:
            ....:     word_size = 8
            sage: not_component = NOT(0, 18, ['input0', 'input1', 'input2', 'input3'], [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7]], 32)
            sage: not_component.cp_xor_differential_first_step_constraints(DummyModel())
            (['array[0..3] of var 0..1: not_0_18;'],
             ['constraint not_0_18[0] = input0[0];',
              'constraint not_0_18[1] = input1[0];',
              'constraint not_0_18[2] = input2[0];',
              'constraint not_0_18[3] = input3[0];'])
        """
        word_size = model.word_size
        cp_declarations = [f"array[0..{(self.output_bit_size - 1) // model.word_size}] of var 0..1: {self.id};"]
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend(
                [
                    f"{id_link}[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
        cp_constraints = [f"constraint {self.id}[{i}] = {input_};" for i, input_ in enumerate(all_inputs)]

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for NOT component for CP xor differential.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.not_component import NOT
            sage: not_component = NOT(0, 0, ['input0'], [list(range(32))], 32)
            sage: declarations, constraints = not_component.cp_xor_differential_propagation_constraints()
            sage: declarations
            []
            sage: constraints[0]
            'constraint not_0_0[0] = input0[0];'
        """
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_constraints = [f"constraint {self.id}[{i}] = {input_};" for i, input_ in enumerate(all_inputs)]

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        return self.cp_xor_differential_first_step_constraints(model)

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for NOT component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(64))], 64)
                        sage: declarations, constraints = not_component.cp_xor_linear_mask_propagation_constraints()
                        sage: declarations
                        ['array[0..63] of var 0..1:not_0_0_i;', 'array[0..63] of var 0..1:not_0_0_o;']
                        sage: constraints[0]
                        'constraint not_0_0_o[0]=not_0_0_i[0];'
        """
        cp_declarations = [
            f"array[0..{self.input_bit_size - 1}] of var 0..1:{self.id}_i;",
            f"array[0..{self.output_bit_size - 1}] of var 0..1:{self.id}_o;",
        ]
        cp_constraints = []
        for i in range(self.input_bit_size):
            cp_constraints.append(f"constraint {self.id}_o[{i}]={self.id}_i[{i}];")

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f"  {self.id} = bit_vector_NOT([{','.join(params)} ])"]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_NOT({params})"]

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        input_int = int(solution["components_values"][f"{output_id_link}_i"]["value"], 16)
        inputs = [int(digit) for digit in format(input_int, f"0{self.input_bit_size}b")]
        component_sign = self.generic_sign_linear_constraints(inputs)
        sign = sign * component_sign
        solution["components_values"][f"{output_id_link}_o"]["sign"] = component_sign
        solution["components_values"][output_id_link] = solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_i"]

        return sign

    def generic_sign_linear_constraints(self, inputs):
        """
        Return the constraints for finding the sign of an NOT component.

        INPUT:

        - ``inputs`` -- **list**; the input of the NOT component

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
            sage: from claasp.components.not_component import NOT
            sage: cipher = NotCipher(bit_size=32)
            sage: not_component = cipher.component_from(0, 0)
            sage: inputs = [0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0]
            sage: not_component.generic_sign_linear_constraints(inputs)
            1
        """
        parity = inputs.count(1) % 2
        if parity == 1:
            sign = -1
        else:
            sign = 1

        return sign

    def milp_constraints(self, model):
        """
        Return lists of variables and constraints for the NOT component for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = NotCipher(bit_size=8)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: not_component = cipher.component_from(0, 0)
            sage: variables, constraints = not_component.milp_constraints(milp)
            sage: len(variables)
            16
            sage: str(constraints[0]).endswith('== 1')
            True
        """
        x = model.binary_variable
        input_bit_size = self.input_bit_size
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        for i in range(input_bit_size):
            constraints.append(x[output_vars[i]] + x[input_vars[i]] == 1)

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for the NOT component for MILP xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = NotCipher(bit_size=8)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: not_component = cipher.component_from(0, 0)
            sage: variables, constraints = not_component.milp_xor_differential_propagation_constraints(milp)
            sage: len(variables)
            16
            sage: str(constraints[0]).count('==')
            1
        """
        x = model.binary_variable
        input_bit_size = self.input_bit_size
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        for i in range(input_bit_size):
            constraints.append(x[output_vars[i]] == x[input_vars[i]])
        result = variables, constraints
        return result

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for the NOT component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = NotCipher(bit_size=8)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: not_component = cipher.component_from(0, 0)
            sage: variables, constraints = not_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: len(variables)
            16
            sage: str(variables[0]).startswith("('x[not_0_0_0_i]'")
            True
        """
        x = model.binary_variable
        output_bit_size = self.output_bit_size
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        for i in range(output_bit_size):
            constraints.append(x[output_vars[i]] == x[input_vars[i]])
        result = variables, constraints
        return result

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for NOT component
        in deterministic truncated XOR differential model.

        INPUTS:

        - ``component`` -- *dict*, the NOT component in Graph Representation

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
            sage: cipher = NotCipher(bit_size=32)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: not_component = cipher.component_from(0, 0)
            sage: variables, constraints = not_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: len(variables)
            64
            sage: str(constraints[0]).count('==')
            1

        """
        x_class = model.trunc_binvar
        input_bit_size = self.input_bit_size
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []

        for i in range(input_bit_size):
            constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        return variables, constraints

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing NOT for SAT CIPHER model

        The list of clauses encodes inequalities ensuring that input variables are correctly negated in the output
        during the NOT operation. Each clause represents a logical condition where the output variable is the inverse of
        the corresponding input variable, enforcing the correct negation. These constraints ensure that the output
        accurately reflects the NOT operation applied to the input.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(32))], 32)
                        sage: output_ids, constraints = not_component.sat_constraints()
                        sage: output_ids[0]
                        'not_0_0_0'
                        sage: constraints[0]
                        'not_0_0_0 input0_0'
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_inequality(output_bit_ids[i], input_bit_ids[i]))

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses representing NOT for SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model

        The list of clauses encodes equalities ensuring that input variables are correctly mapped in the output ones
        during the NOT operation. Note that when performing XOR differential analysis we need equalities.
        Note that encoding symbols for deterministic truncated XOR differential model
        requires two variables per each symbol.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(32))], 32)
                        sage: output_ids, constraints = not_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
                        sage: output_ids[0]
                        'not_0_0_0_0'
                        sage: len(output_ids)
                        64
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        _, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        constraints = []
        for out_id, in_id in zip(out_ids_0, in_ids_0):
            constraints.extend(sat_utils.cnf_equivalent([out_id, in_id]))
        for out_id, in_id_0, in_id_1 in zip(out_ids_1, in_ids_0, in_ids_1):
            constraints.append(f"{in_id_0} {in_id_1} {out_id}")
            constraints.append(f"{in_id_0} -{in_id_1} -{out_id}")

        return out_ids_0 + out_ids_1, constraints

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing NOT for SAT XOR DIFFERENTIAL model

        The list of clauses encodes equalities ensuring that input variables are correctly mapped in the output ones
        during the NOT operation. Note that when performing XOR differential analysis we need equalities.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(32))], 32)
                        sage: output_ids, constraints = not_component.sat_xor_differential_propagation_constraints()
                        sage: output_ids[-1]
                        'not_0_0_31'
                        sage: constraints[0]
                        'not_0_0_0 -input0_0'
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i]]))
        result = output_bit_ids, constraints
        return result

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing NOT for SAT XOR LINEAR model

        The list of clauses encodes equalities ensuring that input variables are correctly mapped in the output ones
        during the NOT operation. Note that when performing XOR linear analysis we need equalities.
        Note that encoding symbols for deterministic truncated XOR differential model
        requires different encodings for input and ouput variables.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(32))], 32)
                        sage: output_ids, constraints = not_component.sat_xor_linear_mask_propagation_constraints()
                        sage: output_ids[0]
                        'not_0_0_0_i'
                        sage: constraints[0]
                        'not_0_0_0_i -not_0_0_0_o'
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([input_bit_ids[i], output_bit_ids[i]]))
        result = input_bit_ids + output_bit_ids, constraints
        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing NOT for SMT CIPHER model

        The list of asserts encodes inequalities ensuring that input variables are correctly negated in the output
        during the NOT operation. Each clause represents a logical condition where the output variable is the inverse of
        the corresponding input variable, enforcing the correct negation. These constraints ensure that the output
        accurately reflects the NOT operation applied to the input.

        INPUT:

        - None

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(64))], 64)
                        sage: output_ids, constraints = not_component.smt_constraints()
                        sage: output_ids[0]
                        'not_0_0_0'
                        sage: constraints[0]
                        '(assert (distinct not_0_0_0 input0_0))'
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_distinct(output_bit_ids[i], input_bit_ids[i])
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing NOT for SMT XOR DIFFERENTIAL model

        The list of clauses encodes equalities ensuring that input variables are correctly mapped in the output ones
        during the NOT operation. Note that when performing XOR differential analysis we need equalities.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(64))], 64)
                        sage: output_ids, constraints = not_component.smt_xor_differential_propagation_constraints()
                        sage: output_ids[-1]
                        'not_0_0_63'
                        sage: constraints[0]
                        '(assert (= not_0_0_0 input0_0))'
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids[i]])
            constraints.append(smt_utils.smt_assert(equation))
        result = output_bit_ids, constraints
        return result

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing NOT for SMT XOR LINEAR model

        The list of clauses encodes equalities ensuring that input variables are correctly mapped in the output ones
        during the NOT operation. Note that when performing XOR linear analysis we need equalities.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

                        sage: from claasp.components.not_component import NOT
                        sage: not_component = NOT(0, 0, ['input0'], [list(range(64))], 64)
                        sage: output_ids, constraints = not_component.smt_xor_linear_mask_propagation_constraints()
                        sage: output_ids[0]
                        'not_0_0_0_i'
                        sage: constraints[0]
                        '(assert (= not_0_0_0_i not_0_0_0_o))'
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        constraints = [
            smt_utils.smt_assert(smt_utils.smt_equivalent((input_bit_id, output_bit_id)))
            for input_bit_id, output_bit_id in zip(input_bit_ids, output_bit_ids)
        ]
        result = input_bit_ids + output_bit_ids, constraints
        return result
