
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
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_and_operation_2_input_bits import (and_LAT,
                                                                                                          and_inequalities)


class MultiInputNonlinearLogicalOperator(Component):

    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, operation):
        component_id = f'{operation}_{current_round_number}_{current_round_number_of_components}'
        component_type = 'word_operation'
        input_len = 0
        for bits in input_bit_positions:
            input_len = input_len + len(bits)
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

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.cms_constraints()
            (['and_0_8_0',
              'and_0_8_1',
              'and_0_8_2',
              ...
              '-and_0_8_11 xor_0_7_11',
              '-and_0_8_11 key_23',
              'and_0_8_11 -xor_0_7_11 -key_23'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model=None):
        return self.sat_xor_differential_propagation_constraints(model)

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_xor_linear_mask_propagation_constraints(model)

    def cp_deterministic_truncated_xor_differential_constraints(self, inverse=False):
        r"""
        Return lists declarations and constraints for AND component CP deterministic truncated xor differential model.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher()
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.cp_deterministic_truncated_xor_differential_constraints()
            ([],
             ['constraint if xor_0_7[0] == 0 /\\ key[12] == 0 then and_0_8[0] = 0 else and_0_8[0] = 2 endif;',
               ...
              'constraint if xor_0_7[11] == 0 /\\ key[23] == 0 then and_0_8[11] = 0 else and_0_8[11] = 2 endif;'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        all_inputs = []
        if inverse:
            for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                all_inputs.extend([f'{id_link}_inverse[{position}]' for position in bit_positions])
        else:
            for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = []
        for i in range(output_size):
            operation = f' == 0 /\\ '.join(all_inputs[i::output_size])
            if inverse:
                new_constraint = f'constraint if {operation} == 0 then {output_id_link}_inverse[{i}] = 0 ' \
                                 f'else {output_id_link}_inverse[{i}] = 2 endif;'
            else:
                new_constraint = f'constraint if {operation} == 0 then {output_id_link}[{i}] = 0 ' \
                                 f'else {output_id_link}[{i}] = 2 endif;'
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_xor_differential_propagation_constraints(self, model):
        """
        Return lists declarations and constraints for the probability of AND component for CP xor differential probability.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: fancy = FancyBlockCipher()
            sage: cp = CpModel(fancy)
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
        for i in range(output_size):
            new_constraint = f'constraint table('
            for j in range(num_add):
                new_constraint = new_constraint + f'[{all_inputs[i + input_len * j]}]++'
            new_constraint = new_constraint + f'[{output_id_link}[{i}]]++[p[{model.c}]],and{num_add}inputs_DDT);'
            cp_constraints.append(new_constraint)
            model.c += 1
            probability.append(model.c)
        model.component_and_probability[output_id_link] = probability
        result = cp_declarations, cp_constraints

        return result

    def generic_sign_linear_constraints(self, inputs, outputs):
        """AND component and OR component override this method."""
        pass

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        input_size = self.input_bit_size
        output_size = self.output_bit_size
        input_int = int(solution['components_values'][f'{output_id_link}_i']['value'], 16)
        output_int = int(solution['components_values'][f'{output_id_link}_o']['value'], 16)
        inputs = [int(digit) for digit in format(input_int, f'0{input_size}b')]
        outputs = [int(digit) for digit in format(output_int, f'0{output_size}b')]
        component_sign = self.generic_sign_linear_constraints(inputs, outputs)
        sign = sign * component_sign
        solution['components_values'][f'{output_id_link}_o']['sign'] = component_sign
        solution['components_values'][output_id_link] = solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_i']

        return sign

    def milp_twoterms_xor_linear_probability_constraints(self, binary_variable, integer_variable,
                                                         input_vars, output_vars, chunk_number):
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
            for index in range(len(output_vars)):
                tmp = x[input_vars[index]] * ineq[1]
                tmp += x[input_vars[index + len(output_vars)]] * ineq[2]
                tmp += x[output_vars[index]] * ineq[3]
                tmp += ineq[0]
                constraints.append(tmp >= 0)

        constraints.append(p[self.id + "_and_probability" + str(chunk_number)] ==
                           sum(x[output_vars[i]] for i in range(len(output_vars))))

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return lists variables and constrains modeling a component of type AND for MILP xor differential probability.

        .. NOTE::

            The constraints are extracted from https://eprint.iacr.org/2020/632.pdf
          The probability is extracted from https://www.iacr.org/archive/fse2014/85400194/85400194.pdf
          Results checked from https://eprint.iacr.org/2021/213.pdf

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: and_component = simon.get_component_from_id("and_0_4")
            sage: variables, constraints = and_component.milp_xor_differential_propagation_constraints(milp)
            sage: variables
            [('x[rot_0_1_0]', x_0),
            ('x[rot_0_1_1]', x_1),
            ...
            ('x[and_0_4_14]', x_46),
            ('x[and_0_4_15]', x_47)]
            sage: constraints
            [0 <= -1*x_32 + x_48,
            0 <= -1*x_33 + x_49,
            ...
            x_64 == 10*x_48 + 10*x_49 + 10*x_50 + 10*x_51 + 10*x_52 + 10*x_53 + 10*x_54 + 10*x_55 + 10*x_56 + 10*x_57 + 10*x_58 + 10*x_59 + 10*x_60 + 10*x_61 + 10*x_62 + 10*x_63]
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
            for index in range(len(output_vars)):
                tmp = 0
                for number_of_chunk in range(self.description[1]):
                    tmp += x[input_vars[index + number_of_chunk * len(output_vars)]] * ineq[number_of_chunk + 1]
                tmp += x[output_vars[index]] * ineq[self.description[1] + 1]
                tmp += x[component_id + "_and_" + str(index)] * ineq[self.description[1] + 2]
                tmp += ineq[0]
                constraints.append(tmp >= 0)
        constraints.append(p[component_id + "_probability"] == 10 * sum(x[component_id + "_and_" + str(i)]
                                                                        for i in range(len(output_vars))))
        result = variables, constraints

        return result

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists variables and constraints to compute the probability for AND component, for k inputs for MILP xor linear probability.

        .. NOTE::

            AND is seen as k parallel application of  a 2x1 S-box, as described in 3.1 of
          https://eprint.iacr.org/2014/973.pdf
          Also see https://eprint.iacr.org/2020/290.pdf

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: and_component = simon.get_component_from_id("and_0_4")
            sage: variables, constraints = and_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[and_0_4_0_i]', x_0),
             ('x[and_0_4_1_i]', x_1),
            ...
             ('x[and_0_4_14_o]', x_46),
             ('x[and_0_4_15_o]', x_47)]
            sage: constraints
            [0 <= -1*x_16 + x_32,
             0 <= -1*x_17 + x_33,
            ...
            0 <= -1*x_15 + x_47,
            x_48 == x_32 + x_33 + x_34 + x_35 + x_36 + x_37 + x_38 + x_39 + x_40 + x_41 + x_42 + x_43 + x_44 + x_45 + x_46 + x_47,
            x_49 == 10*x_48]
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
                binary_variable, integer_variable, input_vars, output_vars, 0)
            constraints.append(p[component_id + "_probability"] == 10 * p[component_id + "_and_probability" + str(0)])

        elif number_of_inputs > 2:
            temp_output_vars = [[f"{var}_temp_and_{i}" for var in output_vars]
                                for i in range(number_of_inputs - 2)]
            variables, constraints = self.milp_twoterms_xor_linear_probability_constraints(
                binary_variable, integer_variable, input_vars[:2 * output_bit_size], temp_output_vars[0], 0)
            for i in range(1, number_of_inputs - 2):
                temp_output_vars.extend([[f"{var}_temp_and_{i}" for var in output_vars]])
                temp_variables, temp_constraints = \
                    self.milp_twoterms_xor_linear_probability_constraints(
                        binary_variable, integer_variable,
                        input_vars[(i + 1) * output_bit_size:(i + 2) * output_bit_size] + temp_output_vars[i - 1],
                        temp_output_vars[i], i)
                variables.extend(temp_variables)
                constraints.extend(temp_constraints)

            temp_variables, temp_constraints = \
                self.milp_twoterms_xor_linear_probability_constraints(
                    binary_variable, integer_variable,
                    input_vars[(number_of_inputs - 1) * output_bit_size: number_of_inputs * output_bit_size] +
                    temp_output_vars[number_of_inputs - 3], output_vars, number_of_inputs - 2)
            variables.extend(temp_variables)
            constraints.extend(temp_constraints)
            constraints.append(
                p[component_id + "_probability"] == 10 * sum(p[component_id + "_and_probability" + str(i)]
                                                             for i in range(number_of_inputs - 1)))
        result = variables, constraints

        return result

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for AND operation in SAT XOR DIFFERENTIAL model.

        .. SEEALSO::

            :ref:`sat-standard` for the format, [ALLW2014]_ for the algorithm.

        .. WARNING::

            This method heavily relies on the fact that the AND operation is always performed using two operands.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.sat_xor_differential_propagation_constraints()
            (['and_0_8_0',
              'and_0_8_1',
              'and_0_8_2',
              ...
              'xor_0_7_11 key_23 -hw_and_0_8_11',
              '-xor_0_7_11 hw_and_0_8_11',
              '-key_23 hw_and_0_8_11'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_and_differential(input_bit_ids[i], input_bit_ids[output_bit_len + i],
                                                              output_bit_ids[i], hw_bit_ids[i]))
        result = output_bit_ids + hw_bit_ids, constraints

        return result

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for AND operation in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.sat_xor_linear_mask_propagation_constraints()
            (['and_0_8_0_i',
              'and_0_8_1_i',
              'and_0_8_2_i',
              ...
              '-and_0_8_23_i hw_and_0_8_11_o',
              '-and_0_8_11_o hw_and_0_8_11_o',
              'and_0_8_11_o -hw_and_0_8_11_o'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(out_suffix)
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_and_linear(input_bit_ids[i], input_bit_ids[output_bit_len + i],
                                                        output_bit_ids[i], hw_bit_ids[i]))
        result = input_bit_ids + output_bit_ids + hw_bit_ids, constraints

        return result

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for AND peration in SMT XOR DIFFERENTIAL model [ALLW2014]_.

        .. WARNING::

            This method heavily relies on the fact that the AND operation is always performed using two operands.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.smt_xor_differential_propagation_constraints()
            (['and_0_8_0',
              'and_0_8_1',
              ...
              'hw_and_0_8_10',
              'hw_and_0_8_11'],
             ['(assert (or (and (not xor_0_7_0) (not key_12) (not and_0_8_0) (not hw_and_0_8_0)) (and xor_0_7_0 hw_and_0_8_0) (and key_12 hw_and_0_8_0)))',
              '(assert (or (and (not xor_0_7_1) (not key_13) (not and_0_8_1) (not hw_and_0_8_1)) (and xor_0_7_1 hw_and_0_8_1) (and key_13 hw_and_0_8_1)))',
              ...
              '(assert (or (and (not xor_0_7_10) (not key_22) (not and_0_8_10) (not hw_and_0_8_10)) (and xor_0_7_10 hw_and_0_8_10) (and key_22 hw_and_0_8_10)))',
              '(assert (or (and (not xor_0_7_11) (not key_23) (not and_0_8_11) (not hw_and_0_8_11)) (and xor_0_7_11 hw_and_0_8_11) (and key_23 hw_and_0_8_11)))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            minterm_0 = smt_utils.smt_and((smt_utils.smt_not(input_bit_ids[i]),
                                           smt_utils.smt_not(input_bit_ids[output_bit_len + i]),
                                           smt_utils.smt_not(output_bit_ids[i]),
                                           smt_utils.smt_not(hw_bit_ids[i])))
            minterm_1 = smt_utils.smt_and((input_bit_ids[i], hw_bit_ids[i]))
            minterm_2 = smt_utils.smt_and((input_bit_ids[output_bit_len + i], hw_bit_ids[i]))
            sop = smt_utils.smt_or((minterm_0, minterm_1, minterm_2))
            constraints.append(smt_utils.smt_assert(sop))
        result = output_bit_ids + hw_bit_ids, constraints

        return result

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for AND operation in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.smt_xor_linear_mask_propagation_constraints()
            (['and_0_8_0_i',
              'and_0_8_1_i',
              ...
              'hw_and_0_8_10_o',
              'hw_and_0_8_11_o'],
             ['(assert (or (and (not and_0_8_0_i) (not and_0_8_12_i) (not and_0_8_0_o) (not hw_and_0_8_0_o)) (and and_0_8_0_o hw_and_0_8_0_o)))',
              '(assert (or (and (not and_0_8_1_i) (not and_0_8_13_i) (not and_0_8_1_o) (not hw_and_0_8_1_o)) (and and_0_8_1_o hw_and_0_8_1_o)))',
              ...
              '(assert (or (and (not and_0_8_10_i) (not and_0_8_22_i) (not and_0_8_10_o) (not hw_and_0_8_10_o)) (and and_0_8_10_o hw_and_0_8_10_o)))',
              '(assert (or (and (not and_0_8_11_i) (not and_0_8_23_i) (not and_0_8_11_o) (not hw_and_0_8_11_o)) (and and_0_8_11_o hw_and_0_8_11_o)))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(out_suffix)
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            minterm_0 = smt_utils.smt_and((smt_utils.smt_not(input_bit_ids[i]),
                                           smt_utils.smt_not(input_bit_ids[output_bit_len + i]),
                                           smt_utils.smt_not(output_bit_ids[i]),
                                           smt_utils.smt_not(hw_bit_ids[i])))
            minterm_1 = smt_utils.smt_and((output_bit_ids[i], hw_bit_ids[i]))
            sop = smt_utils.smt_or((minterm_0, minterm_1))
            constraints.append(smt_utils.smt_assert(sop))
        result = input_bit_ids + output_bit_ids + hw_bit_ids, constraints

        return result
