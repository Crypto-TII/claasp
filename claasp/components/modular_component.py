
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
from claasp.cipher_modules.models.milp.utils import utils as milp_utils


def sat_n_window_heuristc_bit_level(window_size, inputs):
    import claasp.cipher_modules.models.sat.utils.n_window_heuristic_helper
    return getattr(
        claasp.cipher_modules.models.sat.utils.n_window_heuristic_helper,
        f'window_size_{window_size}_cnf')(inputs)


def milp_n_window_heuristic(input_vars, output_vars, component_id, window_size, mip, x):
    def create_window_size_array(j, input_1_vars, input_2_vars, output_vars):
        temp_array = []
        for i in range(1, window_size + 1):
            temp_vars = x[input_1_vars[j - i]] + x[input_2_vars[j - i]] + x[output_vars[j - i]]
            mod_add_var = mip.new_variable(name="mod")
            mip.set_max(mod_add_var, 1)
            u = mip.new_variable(name='u')
            mip.add_constraint(temp_vars == 2 * u['u' + component_id + str(j) +
                                                  str(i)] + mod_add_var["mod" + component_id + str(j) + str(i)])
            temp_array.append(mod_add_var["mod" + component_id + str(j) + str(i)])
        return temp_array

    input_size = int(len(input_vars) / 2)
    input_1_vars = input_vars[:input_size]
    input_2_vars = input_vars[input_size:2 * input_size]
    for j in range(window_size, input_size - 1):
        window_size_array = create_window_size_array(j, input_1_vars, input_2_vars, output_vars)
        mip.add_constraint(mip.sum(window_size_array) <= int(window_size))


def generic_sign_linear_constraints(inputs, outputs):
    """
    Return the constraints for finding the sign of a MODADD/MODSUB component.

    INPUT:

    - ``inputs`` -- **list**; a list representing the inputs to the modadd/modsub
    - ``outputs`` -- **list**; a list representing the output to the modadd/modsub

    EXAMPLES::

        sage: from claasp.components.modular_component import generic_sign_linear_constraints
        sage: input = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]
        sage: output = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        sage: generic_sign_linear_constraints(input, output)
        -1
    """
    sign = +1
    input_size = len(inputs) // 2
    for i in range(input_size):
        if inputs[i] == inputs[input_size + i] and outputs[i] != inputs[i]:
            sign = sign * (-1)

    return sign


class Modular(Component):
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

    def cms_xor_differential_propagation_constraints(self, model):
        return self.sat_xor_differential_propagation_constraints(model)

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for fixing variables in CMS XOR LINEAR model.

        .. SEEALSO::

            :ref:`CMS XOR LINEAR model <cms-linear-standard>` for the format, [LWR2016]_ for the algorithm.

        .. WARNING::

            This method heavily relies on the fact that modular addition/substration is always performed using
            two addenda.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: modadd_component = speck.component_from(0, 1)
            sage: modadd_component.cms_xor_linear_mask_propagation_constraints()
            (['modadd_0_1_0_i',
              'modadd_0_1_1_i',
              'modadd_0_1_2_i',
              ...
              'hw_modadd_0_1_14_o -modadd_0_1_14_o modadd_0_1_30_i',
              'hw_modadd_0_1_15_o modadd_0_1_15_o -modadd_0_1_31_i',
              'hw_modadd_0_1_15_o -modadd_0_1_15_o modadd_0_1_31_i'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = [f'-{hw_bit_ids[0]}']
        constraints.append(f'x -{hw_bit_ids[1]} {output_bit_ids[0]} '
                           f'{input_bit_ids[0]} {input_bit_ids[output_bit_len]}')
        for i in range(2, output_bit_len):
            constraints.append(f'x -{hw_bit_ids[i]} {hw_bit_ids[i - 1]} {output_bit_ids[i - 1]} '
                               f'{input_bit_ids[i - 1]} {input_bit_ids[output_bit_len + i - 1]}')
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_modadd_inequality(hw_bit_ids[i],
                                                               output_bit_ids[i],
                                                               input_bit_ids[i]))
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_modadd_inequality(hw_bit_ids[i],
                                                               output_bit_ids[i],
                                                               input_bit_ids[output_bit_len + i]))
        result = input_bit_ids + output_bit_ids + hw_bit_ids, constraints
        return result

    def cp_deterministic_truncated_xor_differential_constraints(self, inverse=False):
        """
        Return lists of variables and constraints for Modular Addition/Substraction in CP deterministic truncated XOR differential model.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: modadd_component = speck.component_from(0 ,1)
            sage: modadd_component.cp_deterministic_truncated_xor_differential_constraints()
            (['array[0..15] of var 0..2: pre_modadd_0_1_0;',
              'array[0..15] of var 0..2: pre_modadd_0_1_1;'],
             ['constraint pre_modadd_0_1_0[0] = rot_0_0[0];',
               ...
              'constraint pre_modadd_0_1_1[15] = plaintext[31];',
              'constraint modular_addition_word(pre_modadd_0_1_1, pre_modadd_0_1_0, modadd_0_1);'])
        """
        input_id_links = self.input_id_links
        if inverse:
            output_id_link = self.id + '_inverse'
        else:
            output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        num_add = self.description[1]
        all_inputs = []
        if inverse:
            for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                all_inputs.extend([f'{id_link}_inverse[{position}]' for position in bit_positions])
        else:
            for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        input_len = len(all_inputs) // num_add
        cp_declarations = []
        cp_constraints = []
        for i in range(num_add):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..2: pre_{output_id_link}_{i};')
            cp_constraints.extend([f'constraint pre_{output_id_link}_{i}[{j}] = {all_inputs[i * input_len + j]};'
                                   for j in range(input_len)])
        for i in range(num_add, 2 * num_add - 2):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..1: pre_{output_id_link}_{i};')
        for i in range(num_add - 2):
            cp_constraints.append(f'constraint modular_addition_word(pre_{output_id_link}_{num_add - 1}, '
                                  f'pre_{output_id_link}_{i + 1}, pre_{output_id_link}_{num_add + i});')
        cp_constraints.append(f'constraint modular_addition_word(pre_{output_id_link}_{2 * num_add - 3}, '
                              f'pre_{output_id_link}_0, {output_id_link});')

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()
        
    def cp_twoterms_xor_differential_probability(self, input_1, input_2, out, input_length,
                                                 cp_constraints, cp_declarations, c, model):
        if input_1 not in model.modadd_twoterms_mant:
            cp_declarations.append(f'array[0..{input_length - 1}] of var 0..1: Shi_{input_1} = LShift({input_1},1);')
            model.modadd_twoterms_mant.append(input_1)
        if input_2 not in model.modadd_twoterms_mant:
            cp_declarations.append(f'array[0..{input_length - 1}] of var 0..1: Shi_{input_2} = LShift({input_2},1);')
            model.modadd_twoterms_mant.append(input_2)
        if out not in model.modadd_twoterms_mant:
            cp_declarations.append(f'array[0..{input_length - 1}] of var 0..1: Shi_{out} = LShift({out},1);')
            model.modadd_twoterms_mant.append(out)
        cp_declarations.append(f'array[0..{input_length - 1}] of var 0..1: eq_{out} = '
                               f'Eq(Shi_{input_1}, Shi_{input_2}, Shi_{out});')
        cp_constraints.append(f'constraint forall(j in 0..{input_length - 1})(if eq_{out}[j] = '
                              f'1 then (sum([{input_1}[j], {input_2}[j], {out}[j]]) mod 2) = Shi_{input_2}[j] else '
                              f'true endif) /\\ p[{c}] = {input_length}-sum(eq_{out});')

        return cp_declarations, cp_constraints
        
    def cp_xor_differential_propagation_constraints(self, model):
        r"""
        Return lists of declarations and constraints for the probability of Modular Addition/Substraction component for CP xor differential probability.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(speck)
            sage: modadd_component = speck.component_from(0, 1)
            sage: modadd_component.cp_xor_differential_propagation_constraints(cp)
            (['array[0..15] of var 0..1: pre_modadd_0_1_0;',
              ...
              'array[0..15] of var 0..1: eq_modadd_0_1 = Eq(Shi_pre_modadd_0_1_1, Shi_pre_modadd_0_1_0, Shi_modadd_0_1);'],
             ['constraint pre_modadd_0_1_0[0] = rot_0_0[0];',
              ...
              'constraint pre_modadd_0_1_1[15] = plaintext[31];',
              'constraint forall(j in 0..15)(if eq_modadd_0_1[j] = 1 then (sum([pre_modadd_0_1_1[j], pre_modadd_0_1_0[j], modadd_0_1[j]]) mod 2) = Shi_pre_modadd_0_1_0[j] else true endif) /\\ p[0] = 1600-100 * sum(eq_modadd_0_1);'])
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
        for i in range(num_add):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..1: pre_{output_id_link}_{i};')
            cp_constraints.extend([f'constraint pre_{output_id_link}_{i}[{j}] = {all_inputs[i * input_len + j]};'
                                   for j in range(input_len)])
        for i in range(num_add, 2 * num_add - 2):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..1: pre_{output_id_link}_{i};')
        probability = []
        for i in range(num_add - 2):
            self.cp_twoterms_xor_differential_probability(f'pre_{output_id_link}_{num_add - 1}',
                                                          f'pre_{output_id_link}_{i + 1}',
                                                          f'pre_{output_id_link}_{num_add + i}', output_size,
                                                          cp_constraints, cp_declarations, model.c, model)
            probability.append(model.c)
            model.c += 1
        self.cp_twoterms_xor_differential_probability(f'pre_{output_id_link}_{2 * num_add - 3}',
                                                      f'pre_{output_id_link}_0', f'{output_id_link}',
                                                      output_size, cp_constraints, cp_declarations, model.c, model)
        probability.append(model.c)
        model.c += 1
        model.component_and_probability[output_id_link] = probability
        result = cp_declarations, cp_constraints
        return result

    def cp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of declarations and constraints for the probability of Modular Addition/Substraction for CP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
            sage: modadd_component = speck.component_from(0, 1)
            sage: cp = CpModel(speck)
            sage: modadd_component.cp_xor_linear_mask_propagation_constraints(cp)
            (['array[0..31] of var 0..1: modadd_0_1_i;',
              'array[0..15] of var 0..1: modadd_0_1_o;',
              ...
              'constraint pre_modadd_0_1_1[15]=modadd_0_1_i[31];',
              'constraint modadd_linear(pre_modadd_0_1_1, pre_modadd_0_1_0, modadd_0_1_o, p[0]);'])
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        cp_declarations = []
        cp_constraints = []
        num_add = self.description[1]
        input_len = input_size // num_add
        cp_declarations.append(f'array[0..{input_size - 1}] of var 0..1: {output_id_link}_i;')
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1: {output_id_link}_o;')
        probability = []
        for i in range(num_add):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..1: pre_{output_id_link}_{i};')
            for j in range(input_len):
                cp_constraints.append(
                    f'constraint pre_{output_id_link}_{i}[{j}]={output_id_link}_i[{i * input_len + j}];')
        for i in range(num_add, 2 * num_add - 2):
            cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1: pre_{output_id_link}_{i};')
        for i in range(num_add - 2):
            cp_constraints.append(
                f'constraint modadd_linear(pre_{output_id_link}_{num_add - 1}, pre_{output_id_link}_{i + 1}, '
                f'pre_{output_id_link}_{num_add + i}, p[{model.c}]);')
            probability.append(model.c)
            model.c = model.c + 1
        cp_constraints.append(
            f'constraint modadd_linear(pre_{output_id_link}_{2 * num_add - 3}, pre_{output_id_link}_0, '
            f'{output_id_link}_o, p[{model.c}]);')
        probability.append(model.c)
        model.c = model.c + 1
        model.component_and_probability[output_id_link] = probability
        result = cp_declarations, cp_constraints
        return result

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        input_size = self.input_bit_size
        output_size = self.output_bit_size
        input_int = int(solution['components_values'][f'{output_id_link}_i']['value'], 16)
        output_int = int(solution['components_values'][f'{output_id_link}_o']['value'], 16)
        inputs = [int(digit) for digit in format(input_int, f'0{input_size}b')]
        outputs = [int(digit) for digit in format(output_int, f'0{output_size}b')]
        component_sign = generic_sign_linear_constraints(inputs, outputs)
        sign = sign * component_sign
        solution['components_values'][f'{output_id_link}_o']['sign'] = component_sign
        solution['components_values'][output_id_link] = solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_i']

        return sign

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constrains modeling a component of type MODADD/MODSUB for MILP xor differential probability.

        The constraints are extracted from [FWGSH2016]_.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: modadd_component = speck.component_from(0, 1)
            sage: milp = MilpModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = modadd_component.milp_xor_differential_propagation_constraints(milp)
            sage: variables
            [('x[rot_0_0_0]', x_0),
            ('x[rot_0_0_1]', x_1),
            ...
            ('x[modadd_0_1_14]', x_46),
            ('x[modadd_0_1_15]', x_47)]
            sage: constraints
            [x_47 <= x_48,
            x_15 <= x_48,
            ...
            -2 <= -1*x_0 - x_16 - x_17 + x_32 + x_63,
            x_64 == 10*x_49 + 10*x_50 + 10*x_51 + 10*x_52 + 10*x_53 + 10*x_54 + 10*x_55 + 10*x_56 + 10*x_57 + 10*x_58 + 10*x_59 + 10*x_60 + 10*x_61 + 10*x_62 + 10*x_63]
        """
        x = model.binary_variable
        p = model.integer_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        component_id = self.id
        model.non_linear_component_id.append(component_id)
        # 1st condition:
        constraints.append(x[component_id + "_dummy"] >= x[output_vars[output_bit_size - 1]])
        constraints.append(x[component_id + "_dummy"] >= x[input_vars[output_bit_size - 1]])
        constraints.append(x[component_id + "_dummy"] >= x[input_vars[2 * output_bit_size - 1]])
        constraints.append(x[output_vars[output_bit_size - 1]] + x[input_vars[output_bit_size - 1]] +
                           x[input_vars[2 * output_bit_size - 1]] - 2 * x[component_id + "_dummy"] >= 0)
        constraints.append(x[output_vars[output_bit_size - 1]] +
                           x[input_vars[output_bit_size - 1]] + x[input_vars[2 * output_bit_size - 1]] <= 2)
        # 2nd condition:
        # indice 0 for the MSB
        for i in range(output_bit_size - 1, 0, -1):
            constraints.append(x[input_vars[output_bit_size + i]] - x[output_vars[i]] +
                               x[component_id + "_eq_" + str(i)] >= 0)
            constraints.append(x[input_vars[i]] - x[input_vars[output_bit_size + i]] +
                               x[component_id + "_eq_" + str(i)] >= 0)
            constraints.append(-x[input_vars[i]] + x[output_vars[i]] + x[component_id + "_eq_" + str(i)] >= 0)
            constraints.append(-x[input_vars[i]] - x[input_vars[output_bit_size + i]] - x[output_vars[i]] - x[
                component_id + "_eq_" + str(i)] >= -3)
            constraints.append(x[input_vars[i]] + x[input_vars[output_bit_size + i]] + x[output_vars[i]] - x[
                component_id + "_eq_" + str(i)] >= 0)
            constraints.append(
                -x[input_vars[output_bit_size + i]] + x[input_vars[i - 1]] + x[input_vars[output_bit_size + i - 1]] + x[
                    output_vars[i - 1]] + x[component_id + "_eq_" + str(i)] >= 0)
            constraints.append(
                x[input_vars[output_bit_size + i]] + x[input_vars[i - 1]] - x[input_vars[output_bit_size + i - 1]] + x[
                    output_vars[i - 1]] + x[component_id + "_eq_" + str(i)] >= 0)
            constraints.append(
                x[input_vars[output_bit_size + i]] - x[input_vars[i - 1]] + x[input_vars[output_bit_size + i - 1]] + x[
                    output_vars[i - 1]] + x[component_id + "_eq_" + str(i)] >= 0)
            constraints.append(x[input_vars[i]] + x[input_vars[i - 1]] + x[input_vars[output_bit_size + i - 1]] - x[
                output_vars[i - 1]] + x[component_id + "_eq_" + str(i)] >= 0)
            constraints.append(x[output_vars[i]] - x[input_vars[i - 1]] - x[input_vars[output_bit_size + i - 1]] - x[
                output_vars[i - 1]] + x[component_id + "_eq_" + str(i)] >= -2)
            constraints.append(
                -x[input_vars[output_bit_size + i]] - x[input_vars[output_bit_size + i - 1]] + x[input_vars[i - 1]] - x[
                    output_vars[i - 1]] + x[component_id + "_eq_" + str(i)] >= -2)
            constraints.append(
                -x[input_vars[output_bit_size + i]] + x[input_vars[output_bit_size + i - 1]] - x[input_vars[i - 1]] - x[
                    output_vars[i - 1]] + x[component_id + "_eq_" + str(i)] >= -2)
            constraints.append(
                -x[input_vars[output_bit_size + i]] - x[input_vars[output_bit_size + i - 1]] - x[input_vars[i - 1]] + x[
                    output_vars[i - 1]] + x[component_id + "_eq_" + str(i)] >= -2)
        constraints.append(p[component_id + "_probability"] == 10 * sum(
            x[component_id + "_eq_" + str(i)] for i in range(output_bit_size - 1, 0, -1)))
        # the most significant bit is not taken in consideration
        if model.n_window_heuristic is not None:
            milp_n_window_heuristic(input_vars, output_vars, component_id,
                                    model.n_window_heuristic, model.model, x)
        result = variables, constraints
        return result

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for modular
        addition component in deterministic truncated XOR differential model.

        INPUTS:

        - ``component`` -- *dict*, the modular addition component in Graph
          Representation

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: cipher = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: modadd_component = cipher.get_component_from_id("modadd_0_1")
            sage: variables, constraints = modadd_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: constraints
            [x_48 <= 16,
             0 <= x_48,
             0 <= 16 + x_48 - 17*x_49,
             x_48 - 17*x_49 <= 0,
             ...
             2 <= 4 + x_47 - 4*x_157 + 4*x_160,
             x_157 <= x_15 + x_31]
             sage: len(constraints)
             430
        """


        # x_class in [0,2]
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]

        constraints = []
        num_of_inputs = int(self.description[1])
        input_bit_size = int(self.input_bit_size / num_of_inputs)
        output_bit_size = self.output_bit_size
        component_id = self.id

        piv = model.integer_variable
        pivot = piv[component_id + "_pivot"]
        constraints.append(pivot <= output_bit_size -1)
        constraints.append(pivot >= 0)

        # a modadd b = c
        a = [x_class[input_vars[i]] for i in range(input_bit_size)]
        b = [x_class[input_vars[i + input_bit_size]] for i in range(input_bit_size)]
        c = [x_class[output_vars[i]] for i in range(output_bit_size)]

        for i in range(output_bit_size):

            M = output_bit_size + 1

            # i_less = 1 iff i < pivot
            i_less, constr = milp_utils.milp_less(model, i, pivot, M)
            constraints.extend(constr)

            # if i < pivot, i.e i_less = 1 then c = 2
            constraints.append(c[i] >= 2 * i_less)

            # else if i >= pivot (i.e i_less = 0), then a[i+1] = b[i+1] = c[i+1] = 0
            if i < output_bit_size - 1:
                constraints.append(a[i + 1] <= 2 * i_less)
                constraints.append(b[i + 1] <= 2 * i_less)
                constraints.append(c[i + 1] <= 2 * i_less)

            # p_eq = 1 iff i = pivot
            p_eq, eq_constraint = milp_utils.milp_eq(model, i, pivot, M)
            constraints.extend(eq_constraint)

            # if p_eq = 1 (i. pivot == i), then xor(a[i], b[i], c[i])

            # a < 2  iff a_less_2 = 1
            a_less_2, constr = milp_utils.milp_less(model, a[i], 2, model._model.get_max(x_class))
            constraints.extend(constr)

            # b < 2 iff b_less_2 = 1
            b_less_2, constr = milp_utils.milp_less(model, b[i], 2, model._model.get_max(x_class))
            constraints.extend(constr)

            # a_less_2 = 1 and b_less_2 = 1 iff a_b_less_2 = 1
            a_b_less_2, and_constraint = milp_utils.milp_and(model, a_less_2, b_less_2)
            constraints.extend(and_constraint)

            # if p_eq == 1 then:
            # # # # (apply truncated_xor):
            # # # #     if a_b_less_2 == 1 then c = a XOR b
            # # # #     else c = 2
            normal_xor_constr = milp_utils.milp_generalized_xor([a[i], b[i]], c[i])
            truncated_xor_constr = milp_utils.milp_if_then_else(a_b_less_2, normal_xor_constr, [c[i] == 2],
                                                                model._model.get_max(x_class) * num_of_inputs)
            constr = milp_utils.milp_if_then(p_eq, truncated_xor_constr, model._model.get_max(x_class) * num_of_inputs)
            constraints.extend(constr)

            # if pivot > 0 (i.e i > 0 and p_eq = 1), a[pivot] + b[pivot] > 0
            if i > 0:
                constraints.append(a[i] + b[i] >= p_eq)

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for modular
        addition component in deterministic truncated XOR differential model.

        INPUTS:

        - ``component`` -- *dict*, the modular addition component in Graph
          Representation

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: cipher = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: modadd_component = cipher.get_component_from_id("modadd_0_1")
            sage: variables, constraints = modadd_component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)
            sage: variables
            [('x[rot_0_0_0_class_bit_0]', x_0),
             ('x[rot_0_0_0_class_bit_1]', x_1),
            ...
             ('x[modadd_0_1_15_class_bit_0]', x_94),
             ('x[modadd_0_1_15_class_bit_1]', x_95)]
            sage: constraints
            [x_96 == 2*x_0 + x_1,
             x_97 == 2*x_2 + x_3,
            ...
             1 <= 18 - x_30 + x_94 - 17*x_159,
             1 <= 19 - x_62 - x_63 - 17*x_159]

        """

        x = model.binary_variable
        x_class = model.integer_variable

        output_bit_size = self.output_bit_size
        input_id_tuples, output_id_tuples = self._get_input_output_variables_tuples()
        input_ids, output_ids = self._get_input_output_variables()

        linking_constraints = model.link_binary_tuples_to_integer_variables(input_id_tuples + output_id_tuples,
                                                                            input_ids + output_ids)


        variables = [(f"x[{var_elt}]", x[var_elt]) for var_tuple in input_id_tuples + output_id_tuples for var_elt in var_tuple]
        constraints = [] + linking_constraints

        input_vars = [tuple(x[i] for i in _) for _ in input_id_tuples]
        output_vars = [tuple(x[i] for i in _) for _ in output_id_tuples]

        pivot_vars = [x[f"{self.id}_pivot_{_}"] for _ in range(output_bit_size)]


        constraints.extend([sum(pivot_vars) == 1])


        for pivot in range(output_bit_size):
            constraints_pivot = [x_class[f"{self.id}_pivot"] == pivot]
            if pivot > 0:
                constraints_pivot.extend([sum(input_vars[pivot] + input_vars[pivot + output_bit_size]) >= 1])
            for i in range(pivot):
                constraints_pivot.extend([output_vars[i][0] == 1, output_vars[i][1] == 0])
            for i in range(pivot + 1, output_bit_size):
                constraints_pivot.extend([sum(input_vars[i] + input_vars[i + output_bit_size] + output_vars[i]) == 0])
            constraints_pivot.extend(
                milp_utils.milp_xor_truncated(model, input_id_tuples[pivot::output_bit_size][0], input_id_tuples[pivot::output_bit_size][1],
                                              output_id_tuples[pivot]))
            constraints.extend(milp_utils.milp_if_then(pivot_vars[pivot], constraints_pivot, output_bit_size + 1))

        return variables, constraints

    def minizinc_xor_differential_propagation_constraints(self, model):
        r"""
        Return variables and constraints for the component Modular Addition/Substraction for MINIZINC xor differential probability.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: minizinc = MinizincXorDifferentialModel(fancy, sat_or_milp="milp")
            sage: modadd_component = fancy.component_from(1, 9)
            sage: _, constraints = modadd_component.minizinc_xor_differential_propagation_constraints(minizinc)
            sage: constraints[6]
            'constraint modular_addition_word(array1d(0..6-1, [modadd_1_9_x0,modadd_1_9_x1,modadd_1_9_x2,modadd_1_9_x3,modadd_1_9_x4,modadd_1_9_x5]),array1d(0..6-1, [modadd_1_9_x6,modadd_1_9_x7,modadd_1_9_x8,modadd_1_9_x9,modadd_1_9_x10,modadd_1_9_x11]),array1d(0..6-1, [modadd_1_9_y0_0,modadd_1_9_y1_0,modadd_1_9_y2_0,modadd_1_9_y3_0,modadd_1_9_y4_0,modadd_1_9_y5_0]), p_modadd_1_9_0, dummy_modadd_1_9_0, -1)=1;\n'
        """
        def create_block_of_modadd_constraints(input_vars_1_temp, input_vars_2_temp,
                                               output_varstrs_temp, i, round_number):
            mzn_input_array_1 = self._create_minizinc_1d_array_from_list(input_vars_1_temp)
            mzn_input_array_2 = self._create_minizinc_1d_array_from_list(input_vars_2_temp)
            mzn_output_array = self._create_minizinc_1d_array_from_list(output_varstrs_temp)
            dummy_declaration = f'var {model.data_type}: dummy_{component_id}_{i};\n'
            mzn_probability_var = f'p_{component_id}_{i}'
            model.probability_vars.append(mzn_probability_var)
            pr_declaration = (f'array [0..{noutput_bits}-2] of var {model.data_type}:'
                              f'{mzn_probability_var};\n')
            model.probability_modadd_vars_per_round[round_number - 1].append(mzn_probability_var)
            mzn_block_variables = ""
            dummy_id = ""

            if model.sat_or_milp == "milp":
                mzn_block_variables += dummy_declaration
                dummy_id += f'dummy_{component_id}_{i},'
            mzn_block_variables += pr_declaration

            if model.window_size_list:
                round_window_size = model.window_size_list[round_number - 1]
                mzn_block_constraints = (f'constraint modular_addition_word('
                                         f'{mzn_input_array_1},{mzn_input_array_2},{mzn_output_array},'
                                         f' p_{component_id}_{i},'
                                         f' {dummy_id}'
                                         f' {round_window_size}'
                                         f')={model.true_value};\n')
            else:
                mzn_block_constraints = (f'constraint modular_addition_word('
                                         f'{mzn_input_array_1},{mzn_input_array_2},{mzn_output_array},'
                                         f' p_{component_id}_{i},'
                                         f' {dummy_id}'
                                         f' -1'
                                         f')={model.true_value};\n')

            mzn_carry_var = f'carry_{component_id}_{i}'
            modadd_carries_definition = (f'array [0..{noutput_bits}-1] of var {model.data_type}:'
                                         f'{mzn_carry_var};\n')
            mzn_block_variables += modadd_carries_definition
            model.carries_vars.append({'mzn_carry_array_name': mzn_carry_var, 'mzn_carry_array_size': noutput_bits})
            mzn_block_constraints_carries = (f'constraint {mzn_carry_var} = '
                                             f'XOR3('
                                             f'{mzn_input_array_1},{mzn_input_array_2},'
                                             f'{mzn_output_array});\n')
            mzn_block_constraints += mzn_block_constraints_carries

            model.mzn_carries_output_directives.append(f'output ["carries {component_id}:"++show(XOR3('
                                                       f'{mzn_input_array_1},{mzn_input_array_2},'
                                                       f'{mzn_output_array}))++"\\n"];')


            return mzn_block_variables, mzn_block_constraints

        if self.description[0].lower() not in ["modadd", "modsub"]:
            raise ValueError("component must be modular addition, or modular substraction")

        round_number = model.cipher.get_round_from_component_id(self.id)
        var_names = self._define_var(model.input_postfix, model.output_postfix, model.data_type)
        mzn_constraints = []
        component_id = self.id
        ninput_words = self.description[1]
        ninput_bits = self.input_bit_size
        noutput_bits = self.output_bit_size
        input_varstrs = [component_id + "_" + model.input_postfix + str(i) for i in range(ninput_bits)]
        output_varstrs = [component_id + "_" + model.output_postfix + str(i) for i in range(noutput_bits)]
        word_chunk = int(ninput_bits / ninput_words)
        new_output_vars = []

        for i in range(ninput_words - 2):
            new_output_vars_temp = []
            for output_var in output_varstrs:
                mzn_constraints += [f'var {model.data_type}: {output_var}_{i};']
                new_output_vars_temp.append(output_var + "_" + str(i))
            new_output_vars.append(new_output_vars_temp)

        for i in range(ninput_words - 1):
            input_vars_1 = input_varstrs[i * word_chunk:i * word_chunk + word_chunk]
            input_vars_2 = input_varstrs[i * word_chunk + word_chunk:i * word_chunk + word_chunk + word_chunk]
            if i == ninput_words - 2:
                mzn_variables_and_constraints = create_block_of_modadd_constraints(input_vars_1, input_vars_2,
                                                                                   output_varstrs, i, round_number)
            else:
                mzn_variables_and_constraints = create_block_of_modadd_constraints(input_vars_1, input_vars_2,
                                                                                   new_output_vars[i], i, round_number)
            var_names += [mzn_variables_and_constraints[0]]
            mzn_constraints += [mzn_variables_and_constraints[1]]

        return var_names, mzn_constraints

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of variables and constraints for probability of Modular Addition/Substraction for MILP xor linear model, for any arbitrary number of inputs.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: modadd_component = speck.component_from(0, 1)
            sage: variables, constraints = modadd_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[modadd_0_1_0_i]', x_0),
             ('x[modadd_0_1_1_i]', x_1),
            ...
             ('x[modadd_0_1_14_o]', x_46),
             ('x[modadd_0_1_15_o]', x_47)]
            sage: constraints
            [x_48 == 0,
            0 <= -1*x_0 - x_16 + x_32 + x_48 + x_49,
            0 <= x_0 + x_16 - x_32 + x_48 - x_49,
            ...
             -4 <= x_15 + x_31 + x_47 + x_63 + x_64,
             x_65 == x_48 + x_49 + x_50 + x_51 + x_52 + x_53 + x_54 + x_55 + x_56 + x_57 + x_58 + x_59 + x_60 + x_61 + x_62 + x_63,
             x_66 == 10*x_65]
        """
        binary_variable = model.binary_variable
        integer_variable = model.integer_variable
        correlation = integer_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        output_bit_size = self.output_bit_size
        component_id = self.id
        model.non_linear_component_id.append(component_id)
        number_of_inputs = self.description[1]
        variables = []
        constraints = []
        if number_of_inputs == 2:
            variables, constraints = self.twoterms_milp_probability_xor_linear_constraints(binary_variable,
                                                                                           integer_variable,
                                                                                           input_vars,
                                                                                           output_vars, 0)
            constraints.append(correlation[component_id + "_probability"] == 10 *
                               correlation[component_id + "_modadd_probability" + str(0)])

        elif number_of_inputs > 2:
            temp_output_vars = [[f"{var}_temp_modadd_{i}" for var in output_vars]
                                for i in range(number_of_inputs - 2)]
            variables, constraints = \
                self.twoterms_milp_probability_xor_linear_constraints(binary_variable, integer_variable,
                                                                      input_vars[:2 * output_bit_size],
                                                                      temp_output_vars[0], 0)
            for i in range(1, number_of_inputs - 2):
                temp_output_vars.extend([[f"{var}_temp_modadd_{i}" for var in output_vars]])
                temp_variables, temp_constraints = self.twoterms_milp_probability_xor_linear_constraints(
                    binary_variable,
                    integer_variable,
                    input_vars[(i + 1) * output_bit_size:(i + 2) * output_bit_size] + temp_output_vars[i - 1],
                    temp_output_vars[i], i)
                variables.extend(temp_variables)
                constraints.extend(temp_constraints)

            temp_variables, temp_constraints = \
                self.twoterms_milp_probability_xor_linear_constraints(
                    binary_variable, integer_variable,
                    input_vars[(number_of_inputs - 1) * output_bit_size: number_of_inputs * output_bit_size] +
                    temp_output_vars[number_of_inputs - 3],
                    output_vars, number_of_inputs - 2)
            variables.extend(temp_variables)
            constraints.extend(temp_constraints)
            constraints.append(correlation[component_id + "_probability"] ==
                               10 * sum(correlation[component_id + "_modadd_probability" + str(i)]
                                        for i in range(number_of_inputs - 1)))
        result = variables, constraints
        return result

    def sat_xor_differential_propagation_constraints(self, model):
        """
        Return a list of variables and a list of clauses for Modular Addition/Substraction in SAT XOR DIFFERENTIAL model.

        .. SEEALSO::

            :ref:`sat-standard` for the format, [LM2001]_ for the algorithm.

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_model import SatModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatModel(speck)
            sage: modadd_component = speck.component_from(0, 1)
            sage: modadd_component.sat_xor_differential_propagation_constraints(sat)
            (['modadd_0_1_0',
              'modadd_0_1_1',
              'modadd_0_1_2',
              ...
              'modadd_0_1_15 -rot_0_0_15 plaintext_31',
              'modadd_0_1_15 rot_0_0_15 -plaintext_31',
              '-modadd_0_1_15 -rot_0_0_15 -plaintext_31'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        dummy_bit_ids = [f'dummy_{output_bit_ids[i]}' for i in range(output_bit_len - 1)]
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = []
        # Hamming weight
        for i in range(output_bit_len - 1):
            constraints.extend(sat_utils.cnf_hw_lipmaa(hw_bit_ids[i],
                                                       input_bit_ids[i + 1],
                                                       input_bit_ids[output_bit_len + i + 1],
                                                       output_bit_ids[i + 1]))
        constraints.append(f'-{hw_bit_ids[output_bit_len - 1]}')
        # Trail validity
        # <eq(alpha << 1, beta << 1, gamma << 1) & (alfa ^ beta ^ gamma ^ (beta << 1)) = 0>
        for i in range(output_bit_len - 1):
            constraints.extend(sat_utils.cnf_lipmaa(hw_bit_ids[i],
                                                    dummy_bit_ids[i],
                                                    input_bit_ids[output_bit_len + i + 1],
                                                    input_bit_ids[i],
                                                    input_bit_ids[output_bit_len + i],
                                                    output_bit_ids[i]))
        constraints.extend(sat_utils.cnf_xor(output_bit_ids[output_bit_len - 1],
                                             [input_bit_ids[output_bit_len - 1],
                                              input_bit_ids[2 * output_bit_len - 1]]))
        if model.window_size_weight_pr_vars != -1:
            for i in range(output_bit_len - model.window_size_weight_pr_vars):
                constraints.extend(sat_utils.cnf_n_window_heuristic_on_w_vars(
                    hw_bit_ids[i: i + (model.window_size_weight_pr_vars + 1)]))
        component_round_number = model._cipher.get_round_from_component_id(self.id)
        if model.window_size_by_round != None:
            window_size = model.window_size_by_round[component_round_number]
            if window_size != -1:
                for i in range(output_bit_len - window_size):
                    n_window_vars = [0] * ((window_size + 1) * 3)
                    for j in range(window_size + 1):
                        n_window_vars[3 * j + 0] = input_bit_ids[i + j]
                        n_window_vars[3 * j + 1] = input_bit_ids[output_bit_len + i + j]
                        n_window_vars[3 * j + 2] = output_bit_ids[i + j]
                    constraints.extend(sat_n_window_heuristc_bit_level(window_size, n_window_vars))
        result = output_bit_ids + dummy_bit_ids + hw_bit_ids, constraints
        return result

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for fixing variables in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format, [LWR2016]_ for the algorithm.

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: modadd_component = speck.component_from(0, 1)
            sage: modadd_component.sat_xor_linear_mask_propagation_constraints()
            (['modadd_0_1_0_i',
              'modadd_0_1_1_i',
              'modadd_0_1_2_i',
              ...
              'hw_modadd_0_1_14_o -modadd_0_1_14_o modadd_0_1_30_i',
              'hw_modadd_0_1_15_o modadd_0_1_15_o -modadd_0_1_31_i',
              'hw_modadd_0_1_15_o -modadd_0_1_15_o modadd_0_1_31_i'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = [f'-{hw_bit_ids[0]}']
        constraints.extend(sat_utils.cnf_xor(hw_bit_ids[1],
                                             [output_bit_ids[0],
                                              input_bit_ids[0],
                                              input_bit_ids[output_bit_len]]))
        for i in range(2, output_bit_len):
            constraints.extend(sat_utils.cnf_xor(hw_bit_ids[i],
                                                 [hw_bit_ids[i - 1],
                                                  output_bit_ids[i - 1],
                                                  input_bit_ids[i - 1],
                                                  input_bit_ids[output_bit_len + i - 1]]))
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_modadd_inequality(hw_bit_ids[i],
                                                               output_bit_ids[i],
                                                               input_bit_ids[i]))
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_modadd_inequality(hw_bit_ids[i],
                                                               output_bit_ids[i],
                                                               input_bit_ids[output_bit_len + i]))
        result = input_bit_ids + output_bit_ids + hw_bit_ids, constraints
        return result

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for Modular Addition/Substraction in SMT XOR DIFFERENTIAL model [LM2001]_.

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: modadd_component = tea.component_from(0, 1)
            sage: modadd_component.smt_xor_differential_propagation_constraints()
            (['modadd_0_1_0',
              'modadd_0_1_1',
              ...
              'hw_modadd_0_1_30',
              'hw_modadd_0_1_31'],
             ['(assert (= (not hw_modadd_0_1_0) (= shift_0_0_1 key_1 modadd_0_1_1)))',
              '(assert (= (not hw_modadd_0_1_1) (= shift_0_0_2 key_2 modadd_0_1_2)))',
              ...
              '(assert (or hw_modadd_0_1_29 (not (xor shift_0_0_29 key_29 modadd_0_1_29 key_30))))',
              '(assert (or hw_modadd_0_1_30 (not (xor shift_0_0_30 key_30 modadd_0_1_30 key_31))))',
              '(assert (not (xor modadd_0_1_31 shift_0_0_31 key_31)))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = []
        # Hamming weight
        for i in range(output_bit_len - 1):
            operation = smt_utils.smt_equivalent((input_bit_ids[i + 1],
                                                  input_bit_ids[output_bit_len + i + 1],
                                                  output_bit_ids[i + 1]))
            equation = smt_utils.smt_equivalent([smt_utils.smt_not(hw_bit_ids[i]), operation])
            constraints.append(smt_utils.smt_assert(equation))
        constraints.append(smt_utils.smt_assert(smt_utils.smt_not(hw_bit_ids[output_bit_len - 1])))
        # Trail validity
        # <eq(alpha << 1, beta << 1, gamma << 1) & (alfa ^ beta ^ gamma ^ (beta << 1)) = 0>
        for i in range(output_bit_len - 1):
            lipmaa = smt_utils.smt_lipmaa(hw_bit_ids[i],
                                          input_bit_ids[i],
                                          input_bit_ids[output_bit_len + i],
                                          output_bit_ids[i],
                                          input_bit_ids[output_bit_len + i + 1])
            constraints.append(smt_utils.smt_assert(lipmaa))
        lipmaa_lsb = smt_utils.smt_not(smt_utils.smt_xor([output_bit_ids[output_bit_len - 1],
                                                          input_bit_ids[output_bit_len - 1],
                                                          input_bit_ids[2 * output_bit_len - 1]]))
        constraints.append(smt_utils.smt_assert(lipmaa_lsb))
        result = output_bit_ids + hw_bit_ids, constraints
        return result

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for Modular Addition/Substraction in SMT XOR LINEAR model [LWR2016]_.

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: modadd_component = tea.component_from(0, 1)
            sage: modadd_component.smt_xor_linear_mask_propagation_constraints()
            (['modadd_0_1_0_i',
              'modadd_0_1_1_i',
              ...
              'hw_modadd_0_1_30_o',
              'hw_modadd_0_1_31_o'],
             ['(assert (not hw_modadd_0_1_0_o))',
              '(assert (= hw_modadd_0_1_1_o (xor modadd_0_1_0_o modadd_0_1_0_i modadd_0_1_32_i)))',
              '(assert (= hw_modadd_0_1_2_o (xor hw_modadd_0_1_1_o modadd_0_1_1_o modadd_0_1_1_i modadd_0_1_33_i)))',
              ...
              '(assert (=> (xor modadd_0_1_30_o modadd_0_1_62_i) hw_modadd_0_1_30_o))',
              '(assert (=> (xor modadd_0_1_31_o modadd_0_1_63_i) hw_modadd_0_1_31_o))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(output_bit_len)]
        constraints = [smt_utils.smt_assert(smt_utils.smt_not(hw_bit_ids[0]))]
        operation = smt_utils.smt_xor((output_bit_ids[0],
                                       input_bit_ids[0],
                                       input_bit_ids[output_bit_len]))
        equation = smt_utils.smt_equivalent((hw_bit_ids[1], operation))
        constraints.append(smt_utils.smt_assert(equation))
        for i in range(2, output_bit_len):
            operation = smt_utils.smt_xor((hw_bit_ids[i - 1],
                                           output_bit_ids[i - 1],
                                           input_bit_ids[i - 1],
                                           input_bit_ids[output_bit_len + i - 1]))
            equation = smt_utils.smt_equivalent((hw_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))
        for i in range(output_bit_len):
            antecedent = smt_utils.smt_xor((output_bit_ids[i], input_bit_ids[i]))
            implication = smt_utils.smt_implies(antecedent, hw_bit_ids[i])
            constraints.append(smt_utils.smt_assert(implication))
        for i in range(output_bit_len):
            antecedent = smt_utils.smt_xor((output_bit_ids[i], input_bit_ids[output_bit_len + i]))
            implication = smt_utils.smt_implies(antecedent, hw_bit_ids[i])
            constraints.append(smt_utils.smt_assert(implication))
        result = input_bit_ids + output_bit_ids + hw_bit_ids, constraints
        return result

    def twoterms_milp_probability_xor_linear_constraints(self, binary_variable, integer_variable, input_vars,
                                                         output_vars, chunk_number):
        """
        Return lists of variables and constraints for the probability of Modular Addition/Substraction for two inputs MILP xor linear model.

        .. NOTE::

            Using the 8 inequalities as described in Fu2016 https://eprint.iacr.org/2016/407.pdf
          https://github.com/fukai6/milp_speck/blob/master/speck_diff_find.py

        INPUT:

        - ``binary_variable`` -- **boolean MIPVariable**
        - ``integer_variable`` -- **integer MIPVariable**
        - ``input_vars`` -- **list**
        - ``output_vars`` -- **list**
        - ``chunk_number`` -- **integer**
        """
        x = binary_variable
        correlation = integer_variable
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]

        constraints = [x[f"{self.id}_chunk_{chunk_number}_dummy_0"] == 0]
        # from Kai Fu "Note that there is an additional constraint εn = e0"

        output_bit_size = len(output_vars)

        for i in range(output_bit_size):
            constraints.append(x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] -
                               x[input_vars[output_bit_size + i]] -
                               x[input_vars[i]] +
                               x[output_vars[i]] +
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i + 1}"] >= 0)
            constraints.append(x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] +
                               x[input_vars[output_bit_size + i]] +
                               x[input_vars[i]] -
                               x[output_vars[i]] -
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i + 1}"] >= 0)
            constraints.append(x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] +
                               x[input_vars[output_bit_size + i]] -
                               x[input_vars[i]] -
                               x[output_vars[i]] +
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i + 1}"] >= 0)
            constraints.append(x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] -
                               x[input_vars[output_bit_size + i]] +
                               x[input_vars[i]] -
                               x[output_vars[i]] +
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i + 1}"] >= 0)
            constraints.append(x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] +
                               x[input_vars[output_bit_size + i]] -
                               x[input_vars[i]] +
                               x[output_vars[i]] -
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i + 1}"] >= 0)
            constraints.append(x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] -
                               x[input_vars[output_bit_size + i]] +
                               x[input_vars[i]] +
                               x[output_vars[i]] -
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i + 1}"] >= 0)
            constraints.append(x[input_vars[output_bit_size + i]] -
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] +
                               x[input_vars[i]] + x[output_vars[i]] +
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i + 1}"] >= 0)
            constraints.append(x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] +
                               x[input_vars[output_bit_size + i]] + x[input_vars[i]] +
                               x[output_vars[i]] +
                               x[f"{self.id}_chunk_{chunk_number}_dummy_{i + 1}"] >= - 4)

        constraints.append(correlation[f"{self.id}_modadd_probability{chunk_number}"] == sum(
            x[f"{self.id}_chunk_{chunk_number}_dummy_{i}"] for i in range(output_bit_size)))

        return variables, constraints
