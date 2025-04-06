
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

from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.component import Component
from claasp.input import Input


class VariableShift(Component):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, parameter):
        component_id = f'var_shift_{current_round_number}_{current_round_number_of_components}'
        component_type = 'word_operation'
        input_len = 0
        for bits in input_bit_positions:
            input_len = input_len + len(bits)
        description = ['SHIFT_BY_VARIABLE_AMOUNT', parameter]
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for SHIFT BY VARIABLE AMOUNT in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=3)
            sage: variable_shift_component = raiden.component_from(0, 2)
            sage: variable_shift_component.cms_constraints()
            (['var_shift_0_2_0',
              'var_shift_0_2_1',
              'var_shift_0_2_2',
              ...
              '-var_shift_0_2_31 state_3_var_shift_0_2_31',
              '-var_shift_0_2_31 -key_91',
              'var_shift_0_2_31 -state_3_var_shift_0_2_31 key_91'])
        """
        return self.sat_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for SHIFT BY VARIABLE AMOUNT component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=3)
            sage: variable_shift_component = raiden.component_from(0, 2)
            sage: variable_shift_component.cp_constraints()
            (['array[0..31] of var 0..1: pre_var_shift_0_2;',
              'var int: shift_amount_var_shift_0_2;'],
             ['constraint pre_var_shift_0_2[0]=key[0];',
              ...
              'constraint pre_var_shift_0_2[31]=key[31];',
              'constraint bitArrayToInt([key[i]|i in 91..95],shift_amount_var_shift_0_2);',
              'constraint var_shift_0_2=LShift(pre_var_shift_0_2,shift_amount_var_shift_0_2);'])
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
                all_inputs.append(f'{input_id_link[i]}[{input_bit_positions[i][j]}]')
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1: pre_{output_id_link};')
        for i in range(output_size):
            cp_constraints.append(f'constraint pre_{output_id_link}[{i}]={all_inputs[i]};')
        cp_declarations.append(f'var int: shift_amount_{output_id_link};')
        cp_constraints.append(
            f'constraint bitArrayToInt([{input_id_link[numb_of_inp - 1]}[i]|i in '
            f'{input_bit_positions[numb_of_inp - 1][len(input_bit_positions[numb_of_inp - 1]) - bit_for_shift_amount]}'
            f'..{input_bit_positions[numb_of_inp - 1][len(input_bit_positions[numb_of_inp - 1]) - 1]}],'
            f'shift_amount_{output_id_link});')

        if shift_direction == 1:
            cp_constraints.append(
                f'constraint {output_id_link}=RShift(pre_{output_id_link},shift_amount_{output_id_link});')
        else:
            cp_constraints.append(
                f'constraint {output_id_link}=LShift(pre_{output_id_link},shift_amount_{output_id_link});')

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = bit_vector_SHIFT_BY_VARIABLE_AMOUNT([{",".join(params)} ], '
                f'{self.output_bit_size}, {self.description[1]})']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_SHIFT_BY_VARIABLE_AMOUNT({params}, '
                f'{self.output_bit_size}, {self.description[1]})']

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        variable_shift_code = []

        self.select_words(variable_shift_code, word_size)
        wordstring_variables.append(self.id)
        direction = "RIGHT" if self.description[1] >= 0 else "LEFT"
        variable_shift_code.append(f'\tWordString *{self.id} = {direction}_{self.description[0]}(input);')

        if verbosity:
            self.print_word_values(variable_shift_code)

        return variable_shift_code

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        component_sign = 1
        sign = sign * component_sign
        solution['components_values'][f'{output_id_link}_o']['sign'] = component_sign
        solution['components_values'][output_id_link] = solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_i']

        return sign

    def minizinc_xor_differential_propagation_constraints(self, model):
        r"""
        Return variables and constraints for the component SHIFT BY VARIABLE AMOUNT for MINIZINC xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: raiden = RaidenBlockCipher(number_of_rounds=16)
            sage: minizinc = MznModel(raiden)
            sage: variable_shift_component = raiden.component_from(0, 2)
            sage: _, mzn_shift_by_variable_amount_constraints = variable_shift_component.minizinc_xor_differential_propagation_constraints(minizinc)
            sage: mzn_shift_by_variable_amount_constraints[0]
            'constraint LSHIFT_BY_VARIABLE_AMOUNT(array1d(0..32-1, [var_shift_0_2_x0,var_shift_0_2_x1,var_shift_0_2_x2,var_shift_0_2_x3,var_shift_0_2_x4,var_shift_0_2_x5,var_shift_0_2_x6,var_shift_0_2_x7,var_shift_0_2_x8,var_shift_0_2_x9,var_shift_0_2_x10,var_shift_0_2_x11,var_shift_0_2_x12,var_shift_0_2_x13,var_shift_0_2_x14,var_shift_0_2_x15,var_shift_0_2_x16,var_shift_0_2_x17,var_shift_0_2_x18,var_shift_0_2_x19,var_shift_0_2_x20,var_shift_0_2_x21,var_shift_0_2_x22,var_shift_0_2_x23,var_shift_0_2_x24,var_shift_0_2_x25,var_shift_0_2_x26,var_shift_0_2_x27,var_shift_0_2_x28,var_shift_0_2_x29,var_shift_0_2_x30,var_shift_0_2_x31]), 2147483648*var_shift_0_2_x63+1073741824*var_shift_0_2_x62+536870912*var_shift_0_2_x61+268435456*var_shift_0_2_x60+134217728*var_shift_0_2_x59+67108864*var_shift_0_2_x58+33554432*var_shift_0_2_x57+16777216*var_shift_0_2_x56+8388608*var_shift_0_2_x55+4194304*var_shift_0_2_x54+2097152*var_shift_0_2_x53+1048576*var_shift_0_2_x52+524288*var_shift_0_2_x51+262144*var_shift_0_2_x50+131072*var_shift_0_2_x49+65536*var_shift_0_2_x48+32768*var_shift_0_2_x47+16384*var_shift_0_2_x46+8192*var_shift_0_2_x45+4096*var_shift_0_2_x44+2048*var_shift_0_2_x43+1024*var_shift_0_2_x42+512*var_shift_0_2_x41+256*var_shift_0_2_x40+128*var_shift_0_2_x39+64*var_shift_0_2_x38+32*var_shift_0_2_x37+16*var_shift_0_2_x36+8*var_shift_0_2_x35+4*var_shift_0_2_x34+2*var_shift_0_2_x33+1*var_shift_0_2_x32)=array1d(0..32-1, [var_shift_0_2_y0,var_shift_0_2_y1,var_shift_0_2_y2,var_shift_0_2_y3,var_shift_0_2_y4,var_shift_0_2_y5,var_shift_0_2_y6,var_shift_0_2_y7,var_shift_0_2_y8,var_shift_0_2_y9,var_shift_0_2_y10,var_shift_0_2_y11,var_shift_0_2_y12,var_shift_0_2_y13,var_shift_0_2_y14,var_shift_0_2_y15,var_shift_0_2_y16,var_shift_0_2_y17,var_shift_0_2_y18,var_shift_0_2_y19,var_shift_0_2_y20,var_shift_0_2_y21,var_shift_0_2_y22,var_shift_0_2_y23,var_shift_0_2_y24,var_shift_0_2_y25,var_shift_0_2_y26,var_shift_0_2_y27,var_shift_0_2_y28,var_shift_0_2_y29,var_shift_0_2_y30,var_shift_0_2_y31]);\n'
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
            bin_terms.append(f'{2**index_subvector}*{second_subvector_input_vars[index_subvector]}')

        str_shift_amount = "+".join(bin_terms)
        shift_direction = self.description[1]
        mzn_input_array_input = self._create_minizinc_1d_array_from_list(first_subvector_input_vars)
        mzn_input_array_output = self._create_minizinc_1d_array_from_list(output_vars)

        if shift_direction < 0:
            mzn_shift_by_variable_amount_constraints = [f'constraint LSHIFT_BY_VARIABLE_AMOUNT({mzn_input_array_input},'
                                                        f' {str_shift_amount})={mzn_input_array_output};\n']
        else:
            mzn_shift_by_variable_amount_constraints = [f'constraint RSHIFT_BY_VARIABLE_AMOUNT({mzn_input_array_input},'
                                                        f' {str_shift_amount})={mzn_input_array_output};\n']

        return var_names, mzn_shift_by_variable_amount_constraints

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing SHIFT BY VARIABLE AMOUNT for SAT CIPHER model

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=3)
            sage: variable_shift_component = raiden.component_from(0, 2)
            sage: variable_shift_component.sat_constraints()
            (['var_shift_0_2_0',
              'var_shift_0_2_1',
              ...
              'var_shift_0_2_30',
              'var_shift_0_2_31'],
             ['-state_0_var_shift_0_2_0 key_0 key_95',
              'state_0_var_shift_0_2_0 -key_0 key_95',
              ...
              '-var_shift_0_2_31 -key_91',
              'var_shift_0_2_31 -state_3_var_shift_0_2_31 key_91'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        input_ids = input_bit_ids[:output_bit_len]
        shift_ids = input_bit_ids[output_bit_len:]
        number_of_states = int(math.log2(output_bit_len)) - 1
        states = [[f'state_{i}_{output_bit_ids[j]}' for j in range(output_bit_len)]
                  for i in range(number_of_states)]
        constraints = []
        for j in range(output_bit_len - 1):
            constraints.extend(sat_utils.cnf_vshift_id(states[0][j], input_ids[j],
                                                       input_ids[j + 1], shift_ids[output_bit_len - 1]))
        constraints.extend(sat_utils.cnf_vshift_false(states[0][output_bit_len - 1], input_ids[output_bit_len - 1],
                                                      shift_ids[output_bit_len - 1]))
        for i in range(1, number_of_states):
            for j in range(output_bit_len - 2 ** i):
                constraints.extend(sat_utils.cnf_vshift_id(states[i][j], states[i - 1][j],
                                                           states[i - 1][j + 2 ** i],
                                                           shift_ids[output_bit_len - 1 - i]))
            for j in range(output_bit_len - 2 ** i, output_bit_len):
                constraints.extend(sat_utils.cnf_vshift_false(states[i][j], states[i - 1][j],
                                                              shift_ids[output_bit_len - 1 - i]))
        for j in range(output_bit_len - 2 ** number_of_states):
            constraints.extend(sat_utils.cnf_vshift_id(output_bit_ids[j], states[number_of_states - 1][j],
                                                       states[number_of_states - 1][j + 2 ** number_of_states],
                                                       shift_ids[output_bit_len - 1 - number_of_states]))
        for j in range(output_bit_len - 2 ** number_of_states, output_bit_len):
            constraints.extend(sat_utils.cnf_vshift_false(output_bit_ids[j], states[number_of_states - 1][j],
                                                          shift_ids[output_bit_len - 1 - number_of_states]))

        return output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing SHIFT BY VARIABLE AMOUNT for SMT CIPHER model

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=3)
            sage: variable_shift_component = raiden.component_from(0, 2)
            sage: variable_shift_component.smt_constraints()
            (['state_0_var_shift_0_2_0',
              'state_0_var_shift_0_2_1',
              ...
              'var_shift_0_2_30',
              'var_shift_0_2_31'],
             ['(assert (ite key_95 (= state_0_var_shift_0_2_0 key_1) (= state_0_var_shift_0_2_0 key_0)))',
              '(assert (ite key_95 (= state_0_var_shift_0_2_1 key_2) (= state_0_var_shift_0_2_1 key_1)))',
              ...
              '(assert (ite key_91 (not var_shift_0_2_30) (= var_shift_0_2_30 state_3_var_shift_0_2_30)))',
              '(assert (ite key_91 (not var_shift_0_2_31) (= var_shift_0_2_31 state_3_var_shift_0_2_31)))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        input_ids = input_bit_ids[:output_bit_len]
        shift_ids = input_bit_ids[output_bit_len:]
        states = []
        number_of_states = int(math.log2(output_bit_len)) - 1
        for i in range(number_of_states):
            states.append([f'state_{i}_{output_bit_ids[j]}' for j in range(output_bit_len)])
        constraints = []
        if len(states) <= 0:
            raise ValueError('states must not be empty')

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
            for j in range(output_bit_len - 2 ** i):
                consequent = smt_utils.smt_equivalent((states[i][j], states[i - 1][j + 2 ** i]))
                alternative = smt_utils.smt_equivalent((states[i][j], states[i - 1][j]))
                shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1 - i], consequent, alternative)
                constraints.append(smt_utils.smt_assert(shift))
            for j in range(output_bit_len - 2 ** i, output_bit_len):
                consequent = smt_utils.smt_not(states[i][j])
                alternative = smt_utils.smt_equivalent((states[i][j], states[i - 1][j]))
                shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1 - i], consequent, alternative)
                constraints.append(smt_utils.smt_assert(shift))

        # last shift
        for j in range(output_bit_len - 2 ** number_of_states):
            consequent = smt_utils.smt_equivalent(
                (output_bit_ids[j], states[number_of_states - 1][j + 2 ** number_of_states]))
            alternative = smt_utils.smt_equivalent((output_bit_ids[j], states[number_of_states - 1][j]))
            shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1 - number_of_states], consequent, alternative)
            constraints.append(smt_utils.smt_assert(shift))
        for j in range(output_bit_len - 2 ** number_of_states, output_bit_len):
            consequent = smt_utils.smt_not(output_bit_ids[j])
            alternative = smt_utils.smt_equivalent((output_bit_ids[j], states[number_of_states - 1][j]))
            shift = smt_utils.smt_ite(shift_ids[output_bit_len - 1 - number_of_states], consequent, alternative)
            constraints.append(smt_utils.smt_assert(shift))

        # create state variables list
        state_bit_ids = [bit_id for state in states for bit_id in state]

        return state_bit_ids + output_bit_ids, constraints
