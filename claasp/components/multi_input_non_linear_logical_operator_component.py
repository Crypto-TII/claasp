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
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_and_operation_2_input_bits import (
    and_LAT,
    and_inequalities,
)
from claasp.name_mappings import WORD_OPERATION


class MultiInputNonlinearLogicalOperator(Component):
    """
    Construct a generic multi-input non-linear logical operator component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``operation`` -- **string**; operation name used to build the component description/id (for example ``'and'``).

    NOTE:

        The number of operands is automatically inferred as
        ``sum(len(p) for p in input_bit_positions) / output_bit_size``.
        For example, two input groups of 2 bits each with ``output_bit_size=2`` give a 2-input operation;
        three input groups of 2 bits each give a 3-input operation.

    EXAMPLES::

        sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
        sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['a', 'b'], [[0, 1], [0, 1]], 2, 'and')
        sage: print(component.id)
        and_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['AND', 2]
        sage: component3 = MultiInputNonlinearLogicalOperator(0, 1, ['a', 'b', 'c'], [[0, 1], [0, 1], [0, 1]], 2, 'and')
        sage: print(component3.description)  # 6 total bits / output_bit_size 2 = 3 operands
        ['AND', 3]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        operation,
    ):
        component_id = f"{operation}_{current_round_number}_{current_round_number_of_components}"
        component_type = WORD_OPERATION
        input_len = sum(map(len, input_bit_positions))
        description = [operation.upper(), int(input_len / output_bit_size)]
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for AND operation in CMS CIPHER model.

        This method support AND operation using more than two operands.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        TESTS:

            This class is a generic base class. The actual behavior of ``cms_constraints``
            is exercised in concrete subclasses that implement ``sat_constraints``.
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model=None):
        return self.sat_xor_differential_propagation_constraints(model)

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_xor_linear_mask_propagation_constraints(model)

    def cp_deterministic_truncated_xor_differential_constraints(self):
        r"""
        Return lists of declarations and constraints for a multi-input nonlinear logical operator
        in the CP deterministic truncated XOR differential model.

        This method contains standalone base-class logic and is therefore documented with a
        direct instantiation of ``MultiInputNonlinearLogicalOperator``.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: component.cp_deterministic_truncated_xor_differential_constraints()
            ([],
             ['constraint if input1[0] == 0 /\\ input2[0] == 0 then and_0_0[0] = 0 else and_0_0[0] = 2 endif;',
              'constraint if input1[1] == 0 /\\ input2[1] == 0 then and_0_0[1] = 0 else and_0_0[1] = 2 endif;'])
        """
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_constraints = []
        for i in range(self.output_bit_size):
            operation = " == 0 /\\ ".join(all_inputs[i :: self.output_bit_size])
            cp_constraint = f"constraint if {operation} == 0 then {self.id}[{i}] = 0 else {self.id}[{i}] = 2 endif;"
            cp_constraints.append(cp_constraint)

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        r"""
        Return lists of declarations and constraints for a multi-input nonlinear logical operator
        for CP wordwise deterministic truncated XOR differential.

        This is for the deterministic truncated xor differential trail search.

        TESTING NOTE:

            This method contains real base-class logic but only depends on the model's
            ``word_size`` attribute. The doctest therefore uses a minimal dummy model
            instead of a full cipher-backed instantiation.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: class DummyModel:
            ....:     word_size = 2
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())[:1]
            ([],)
        """
        cp_declarations = []
        all_inputs_value = []
        all_inputs_active = []
        numadd = self.description[1]
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
        input_len = len(all_inputs_value) // numadd
        cp_constraints = []
        for i in range(input_len):
            operation = " == 0 /\\ ".join(all_inputs_active[i::input_len])
            new_constraint = (
                f"constraint if {operation} == 0 then {self.id}_active[{i}] = 0 "
                f"/\\ {self.id}_value[{i}] = 0 else {self.id}_active[{i}] = 3 "
                f"/\\ {self.id}_value[{i}] = -2 endif;"
            )
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model):
        """
        Return lists of declarations and constraints for the probability of a multi-input nonlinear
        logical operator in the CP XOR differential model.

        .. NOTE::

            For the operators represented by this base class (currently ``AND`` and ``OR``),
            the same DDT table is used. This is why the generated MiniZinc constraint names
            still reference ``and{num_add}inputs_DDT``.

        TESTING NOTE:

            This method contains real base-class logic but only depends on the model's
            ``c`` counter and ``component_and_probability`` dictionary. The doctest uses a
            minimal dummy model rather than a full cipher/model integration setup.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: class DummyModel:
            ....:     def __init__(self):
            ....:         self.c = 0
            ....:         self.component_and_probability = {}
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: component.cp_xor_differential_propagation_constraints(DummyModel())
            ([],
             ['constraint table([input1[0]]++[input2[0]]++[and_0_0[0]]++[p[0]],and2inputs_DDT);',
              'constraint table([input1[1]]++[input2[1]]++[and_0_0[1]]++[p[1]],and2inputs_DDT);'])
        """
        num_add = self.description[1]
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        input_len = len(all_inputs) // num_add
        cp_declarations = []
        cp_constraints = []
        probability = []
        for i in range(self.output_bit_size):
            inputs = "++".join(f"[{all_inputs[i + input_len * j]}]" for j in range(num_add))
            cp_constraint = f"constraint table({inputs}++[{self.id}[{i}]]++[p[{model.c}]],and{num_add}inputs_DDT);"
            cp_constraints.append(cp_constraint)
            model.c += 1
            probability.append(model.c)
        model.component_and_probability[self.id] = probability

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints_boomerang(self, model):
        """
        Return lists declarations and constraints for the probability of AND component for CP xor differential probability.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: fancy = FancyBlockCipher()
            sage: cp = MznModel(fancy)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.cp_xor_differential_propagation_constraints(cp)
            ([],
             ['constraint table([xor_0_7[0]]++[key[12]]++[and_0_8[0]]++[p[0]],and2inputs_DDT);',
               ...
              'constraint table([xor_0_7[11]]++[key[23]]++[and_0_8[11]]++[p[11]],and2inputs_DDT);'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        num_add = self.description[1]
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        input_len = len(all_inputs) // num_add
        cp_declarations = []
        cp_constraints = []
        probability = []
        probability_upper = []
        probability_lower = []
        for i in range(output_size):
            new_constraint = f'constraint table('
            for j in range(num_add):
                new_constraint = new_constraint + f'[{all_inputs[i + input_len * j]}]++'
            if 'upper' in output_id_link:
                new_constraint = new_constraint + f'[{output_id_link}[{i}]]++[upper_p[{model.c_upper}]],upper_and{num_add}inputs_DDT);'
                probability_upper.append(model.c_upper)
                model.component_and_probability[output_id_link] = probability_upper
                model.c_upper += 1 
            if 'lower' in output_id_link:
                new_constraint = new_constraint + f'[{output_id_link}[{i}]]++[lower_p[{model.c_lower}]],lower_and{num_add}inputs_DDT);'
                probability_lower.append(model.c_lower)
                model.component_and_probability[output_id_link] = probability_lower
                model.c_lower += 1

            cp_constraints.append(new_constraint)

        result = cp_declarations, cp_constraints

        return result

    def generic_sign_linear_constraints(self, inputs, outputs):
        """AND component and OR component override this method."""
        pass

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        input_int = int(solution["components_values"][f"{output_id_link}_i"]["value"], 16)
        output_int = int(solution["components_values"][f"{output_id_link}_o"]["value"], 16)
        inputs = [int(digit) for digit in format(input_int, f"0{self.input_bit_size}b")]
        outputs = [int(digit) for digit in format(output_int, f"0{self.output_bit_size}b")]
        component_sign = self.generic_sign_linear_constraints(inputs, outputs)
        sign = sign * component_sign
        solution["components_values"][f"{output_id_link}_o"]["sign"] = component_sign
        solution["components_values"][output_id_link] = solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_i"]

        return sign

    def milp_twoterms_xor_linear_probability_constraints(
        self, binary_variable, integer_variable, input_vars, output_vars, chunk_number
    ):
        """
        Return a variables list and a constraints list to compute the probability for AND component, for two inputs for MILP xor linear probability.

        .. NOTE::

            AND is seen as a 2x1 S-box, as described in 3.1 of https://eprint.iacr.org/2014/973.pdf
          https://eprint.iacr.org/2020/290.pdf

        INPUT:

        - ``binary_variable`` -- **boolean MIPVariable object**
        - ``integer_variable`` -- **integer MIPVariable object**
        - ``input_vars`` -- **list**
        - ``output_vars`` -- **list**
        - ``chunk_number`` -- **integer**
        """
        x = binary_variable
        p = integer_variable
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        inequalities = and_LAT()

        for ineq in inequalities:
            for i, output_var in enumerate(output_vars):
                tmp = x[input_vars[i]] * ineq[1]
                tmp += x[input_vars[i + len(output_vars)]] * ineq[2]
                tmp += x[output_var] * ineq[3]
                tmp += ineq[0]
                constraints.append(tmp >= 0)

        constraints.append(
            p[f"{self.id}_and_probability{chunk_number}"] == sum(x[output_var] for output_var in output_vars)
        )

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return lists of variables and constraints modeling a multi-input nonlinear logical operator
        for MILP XOR differential probability.

        .. NOTE::

            The constraints are extracted from https://eprint.iacr.org/2020/632.pdf
          The probability is extracted from https://www.iacr.org/archive/fse2014/85400194/85400194.pdf
          Results checked from https://eprint.iacr.org/2021/213.pdf

        TESTING NOTE:

                The base class owns this constraint-generation logic. The doctest keeps the
                setup minimal by using a small dummy MILP model backed by ``MixedIntegerLinearProgram``
                instead of constructing a full cipher-specific model instance.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: from sage.numerical.mip import MixedIntegerLinearProgram
            sage: class DummyMilp:
            ....:     def __init__(self):
            ....:         self._model = MixedIntegerLinearProgram(maximization=False, solver='GLPK')
            ....:         self.binary_variable = self._model.new_variable(binary=True)
            ....:         self.integer_variable = self._model.new_variable(integer=True, nonnegative=True)
            ....:         self.non_linear_component_id = []
            ....:         self.weight_precision = 2
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: variables, constraints = component.milp_xor_differential_propagation_constraints(DummyMilp())
            sage: variables[:1]
            [('x[input1_0]', x_0)]
            sage: len(constraints) > 0
            True
        """
        x = model.binary_variable
        p = model.integer_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        component_id = self.id
        model.non_linear_component_id.append(component_id)
        inequalities = and_inequalities()
        for ineq in inequalities:
            for i, output_var in enumerate(output_vars):
                tmp = 0
                for number_of_chunk in range(self.description[1]):
                    tmp += x[input_vars[i + number_of_chunk * len(output_vars)]] * ineq[number_of_chunk + 1]
                tmp += x[output_var] * ineq[self.description[1] + 1]
                tmp += x[f"{component_id}_and_{i}"] * ineq[self.description[1] + 2]
                tmp += ineq[0]
                constraints.append(tmp >= 0)
        constraints.append(
            p[component_id + "_probability"]
            == (10**model.weight_precision) * sum(x[component_id + "_and_" + str(i)] for i in range(len(output_vars)))
        )
        result = variables, constraints

        return result

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of variables and constraints to compute the probability for a multi-input
        nonlinear logical operator for MILP XOR linear probability.

        .. NOTE::

            The operators represented by this base class are modeled through the same
            underlying AND-based LAT inequalities. See 3.1 of
            https://eprint.iacr.org/2014/973.pdf
            Also see https://eprint.iacr.org/2020/290.pdf

        TESTING NOTE:

            The base class owns this logic, but the method needs a few MILP services.
            The doctest therefore uses a small dummy MILP model rather than a full
            cipher-backed integration setup.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: from sage.numerical.mip import MixedIntegerLinearProgram
            sage: class DummyMilp:
            ....:     def __init__(self):
            ....:         self._model = MixedIntegerLinearProgram(maximization=False, solver='GLPK')
            ....:         self.binary_variable = self._model.new_variable(binary=True)
            ....:         self.integer_variable = self._model.new_variable(integer=True, nonnegative=True)
            ....:         self.non_linear_component_id = []
            ....:         self.weight_precision = 2
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: variables, constraints = component.milp_xor_linear_mask_propagation_constraints(DummyMilp())
            sage: variables[:1]
            [('x[and_0_0_0_i]', x_0)]
            sage: len(constraints) > 0
            True
        """
        binary_variable = model.binary_variable
        integer_variable = model.integer_variable
        non_linear_component_id = model.non_linear_component_id
        p = integer_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        output_bit_size = self.output_bit_size
        component_id = self.id
        non_linear_component_id.append(component_id)
        number_of_inputs = self.description[1]
        variables = []
        constraints = []
        if number_of_inputs == 2:
            variables, constraints = self.milp_twoterms_xor_linear_probability_constraints(
                binary_variable, integer_variable, input_vars, output_vars, 0
            )
            constraints.append(
                p[component_id + "_probability"]
                == (10**model.weight_precision) * p[component_id + "_and_probability" + str(0)]
            )

        elif number_of_inputs > 2:
            temp_output_vars = [[f"{var}_temp_and_{i}" for var in output_vars] for i in range(number_of_inputs - 2)]
            variables, constraints = self.milp_twoterms_xor_linear_probability_constraints(
                binary_variable, integer_variable, input_vars[: 2 * output_bit_size], temp_output_vars[0], 0
            )
            for i in range(1, number_of_inputs - 2):
                temp_output_vars.extend([[f"{var}_temp_and_{i}" for var in output_vars]])
                temp_variables, temp_constraints = self.milp_twoterms_xor_linear_probability_constraints(
                    binary_variable,
                    integer_variable,
                    input_vars[(i + 1) * output_bit_size : (i + 2) * output_bit_size] + temp_output_vars[i - 1],
                    temp_output_vars[i],
                    i,
                )
                variables.extend(temp_variables)
                constraints.extend(temp_constraints)

            temp_variables, temp_constraints = self.milp_twoterms_xor_linear_probability_constraints(
                binary_variable,
                integer_variable,
                input_vars[(number_of_inputs - 1) * output_bit_size : number_of_inputs * output_bit_size]
                + temp_output_vars[number_of_inputs - 3],
                output_vars,
                number_of_inputs - 2,
            )
            variables.extend(temp_variables)
            constraints.extend(temp_constraints)
            constraints.append(
                p[component_id + "_probability"]
                == (10**model.weight_precision)
                * sum(p[component_id + "_and_probability" + str(i)] for i in range(number_of_inputs - 1))
            )
        result = variables, constraints

        return result

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses representing AND/OR for SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: component.sat_bitwise_deterministic_truncated_xor_differential_constraints()[:1]
            (['and_0_0_0_0', 'and_0_0_1_0', 'and_0_0_0_1', 'and_0_0_1_1'],)
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        out_len, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        constraints = []
        for i in range(out_len):
            constraints.extend([f"{out_ids_0[i]} -{in_id}" for in_id in in_ids_0[i::out_len]])
            constraints.extend([f"{out_ids_0[i]} -{in_id}" for in_id in in_ids_1[i::out_len]])
            constraints.append(f"{out_ids_0[i]} -{out_ids_1[i]}")
            clause = f"{' '.join(in_ids_0[i::out_len])} {' '.join(in_ids_1[i::out_len])} -{out_ids_0[i]}"
            constraints.append(clause)

        return out_ids_0 + out_ids_1, constraints

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing AND/OR for SAT XOR DIFFERENTIAL model

        .. SEEALSO::

            :ref:`sat-standard` for the format, [ALLW2014]_ for the algorithm.

        .. WARNING::

            This method heavily relies on the fact that the AND operation is always performed using two operands.

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: component.sat_xor_differential_propagation_constraints()[:1]
            (['and_0_0_0', 'and_0_0_1', 'hw_and_0_0_0', 'hw_and_0_0_1'],)
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f"hw_{output_bit_ids[i]}" for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(
                sat_utils.cnf_and_differential(
                    input_bit_ids[i], input_bit_ids[output_bit_len + i], output_bit_ids[i], hw_bit_ids[i]
                )
            )
        result = output_bit_ids + hw_bit_ids, constraints

        return result

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing AND/OR for SAT XOR LINEAR model

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: component.sat_xor_linear_mask_propagation_constraints()[:1]
            (['and_0_0_0_i', 'and_0_0_1_i', 'and_0_0_2_i', 'and_0_0_3_i', 'and_0_0_0_o', 'and_0_0_1_o', 'hw_and_0_0_0_o', 'hw_and_0_0_1_o'],)
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(out_suffix)
        hw_bit_ids = [f"hw_{output_bit_ids[i]}" for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(
                sat_utils.cnf_and_linear(
                    input_bit_ids[i], input_bit_ids[output_bit_len + i], output_bit_ids[i], hw_bit_ids[i]
                )
            )
        result = input_bit_ids + output_bit_ids + hw_bit_ids, constraints

        return result

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing AND/OR for SMT XOR DIFFERENTIAL model

        .. SEEALSO::

            The algorithm can be found in [ALLW2014]_.

        .. WARNING::

            This method heavily relies on the fact that the AND operation is always performed using two operands.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: component.smt_xor_differential_propagation_constraints()[:1]
            (['and_0_0_0', 'and_0_0_1', 'hw_and_0_0_0', 'hw_and_0_0_1'],)
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f"hw_{output_bit_ids[i]}" for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            minterm_0 = smt_utils.smt_and(
                (
                    smt_utils.smt_not(input_bit_ids[i]),
                    smt_utils.smt_not(input_bit_ids[output_bit_len + i]),
                    smt_utils.smt_not(output_bit_ids[i]),
                    smt_utils.smt_not(hw_bit_ids[i]),
                )
            )
            minterm_1 = smt_utils.smt_and((input_bit_ids[i], hw_bit_ids[i]))
            minterm_2 = smt_utils.smt_and((input_bit_ids[output_bit_len + i], hw_bit_ids[i]))
            sop = smt_utils.smt_or((minterm_0, minterm_1, minterm_2))
            constraints.append(smt_utils.smt_assert(sop))
        result = output_bit_ids + hw_bit_ids, constraints

        return result

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing AND/OR for SMT XOR LINEAR model

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
            sage: component = MultiInputNonlinearLogicalOperator(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 'and')
            sage: component.smt_xor_linear_mask_propagation_constraints()[:1]
            (['and_0_0_0_i', 'and_0_0_1_i', 'and_0_0_2_i', 'and_0_0_3_i', 'and_0_0_0_o', 'and_0_0_1_o', 'hw_and_0_0_0_o', 'hw_and_0_0_1_o'],)
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(out_suffix)
        hw_bit_ids = [f"hw_{output_bit_ids[i]}" for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            minterm_0 = smt_utils.smt_and(
                (
                    smt_utils.smt_not(input_bit_ids[i]),
                    smt_utils.smt_not(input_bit_ids[output_bit_len + i]),
                    smt_utils.smt_not(output_bit_ids[i]),
                    smt_utils.smt_not(hw_bit_ids[i]),
                )
            )
            minterm_1 = smt_utils.smt_and((output_bit_ids[i], hw_bit_ids[i]))
            sop = smt_utils.smt_or((minterm_0, minterm_1))
            constraints.append(smt_utils.smt_assert(sop))
        result = input_bit_ids + output_bit_ids + hw_bit_ids, constraints

        return result
