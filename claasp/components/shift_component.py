
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


class SHIFT(Component):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, parameter):
        component_id = f'shift_{current_round_number}_{current_round_number_of_components}'
        component_type = 'word_operation'
        description = ['SHIFT', parameter]
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for bitwise SHIFT.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: shift_component = fancy.get_component_from_id("shift_1_12")
            sage: algebraic = AlgebraicModel(fancy)
            sage: shift_component.algebraic_polynomials(algebraic)
            [shift_1_12_y0,
             shift_1_12_y1,
             shift_1_12_y2,
             shift_1_12_y3 + shift_1_12_x0,
             shift_1_12_y4 + shift_1_12_x1,
             shift_1_12_y5 + shift_1_12_x2]
        """
        if self.description[0].lower() != "shift":
            raise ValueError("component must be bitwise shift")

        ninputs = noutputs = self.output_bit_size
        shift_constant = self.description[1] % noutputs
        input_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        ring_R = model.ring()
        x = list(map(ring_R, input_vars))
        y = list(map(ring_R, output_vars))

        polynomials = [y[i] for i in range(shift_constant)] + \
                      [y[shift_constant:][i] + x[i] for i in range(noutputs - shift_constant)]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for shift in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: shift_component = tea.component_from(0, 0)
            sage: shift_component.cms_constraints()
            (['shift_0_0_0',
              'shift_0_0_1',
              'shift_0_0_2',
              ...
              '-shift_0_0_29',
              '-shift_0_0_30',
              '-shift_0_0_31'])
        """
        return self.sat_constraints()

    def cms_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cms_constraints()

    def cms_xor_differential_propagation_constraints(self, model=None):
        return self.cms_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_xor_linear_mask_propagation_constraints()

    def cp_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for SHIFT component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: shift_component = tea.component_from(0, 0)
            sage: shift_component.cp_constraints()
            ([],
             ['constraint shift_0_0[0] = plaintext[36];',
              ...
              'constraint shift_0_0[27] = plaintext[63];',
              'constraint shift_0_0[28] = 0;',
              'constraint shift_0_0[29] = 0;',
              'constraint shift_0_0[30] = 0;',
              'constraint shift_0_0[31] = 0;'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        shift_amount = abs(self.description[1])
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        if shift_amount == self.description[1]:
            cp_constraints = [f'constraint {output_id_link}[{i}] = 0;' for i in range(shift_amount)]
            cp_constraints.extend([f'constraint {output_id_link}[{i}] = {all_inputs[i - shift_amount]};'
                                   for i in range(shift_amount, output_size)])
        else:
            cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[i + shift_amount]};'
                              for i in range(output_size - shift_amount)]
            cp_constraints.extend([f'constraint {output_id_link}[{i}] = 0;'
                                   for i in range(output_size - shift_amount, output_size)])

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_constraints()

    def cp_inverse_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for SHIFT component for CP INVERSE CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: shift_component = tea.component_from(0, 0)
            sage: shift_component.cp_inverse_constraints()
            ([],
             ['constraint shift_0_0_inverse[0] = plaintext[36];',
              ...
              'constraint shift_0_0_inverse[27] = plaintext[63];',
              'constraint shift_0_0_inverse[28] = 0;',
               ...
              'constraint shift_0_0_inverse[31] = 0;'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        shift_amount = abs(self.description[1])
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        if shift_amount == self.description[1]:
            cp_constraints = [f'constraint {output_id_link}_inverse[{i}] = 0;' for i in range(shift_amount)]
            cp_constraints.extend([f'constraint {output_id_link}_inverse[{i}] = {all_inputs[i - shift_amount]};'
                                   for i in range(shift_amount, output_size)])
        else:
            cp_constraints = [f'constraint {output_id_link}_inverse[{i}] = {all_inputs[i + shift_amount]};'
                              for i in range(output_size - shift_amount)]
            cp_constraints.extend([f'constraint {output_id_link}_inverse[{i}] = 0;'
                                   for i in range(output_size - shift_amount, output_size)])

        return cp_declarations, cp_constraints

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return a list of CP declarations and a list of CP constraints for shift component.

        This is for CP wordwise deterministic truncated xor differential trail search.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: from claasp.components.shift_component import SHIFT
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: shift_component = SHIFT(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'], [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
            sage: shift_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)
            ([],
             ['constraint shift_0_18_active[0] = sbox_0_6_active[0];',
               ...
              'constraint shift_0_18_value[3] = 0;'])
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        word_size = model.word_size
        shift_amount = abs(self.description[1]) // word_size
        all_inputs_active = []
        all_inputs_value = []
        cp_declarations = []
        for id_link, bit_positions in zip(input_id_link, input_bit_positions):
            all_inputs_active.extend([f'{id_link}_active[{bit_positions[j * word_size] // word_size}]'
                                      for j in range(len(bit_positions) // word_size)])
        for id_link, bit_positions in zip(input_id_link, input_bit_positions):
            all_inputs_value.extend([f'{id_link}_value[{bit_positions[j * word_size] // word_size}]'
                                     for j in range(len(bit_positions) // word_size)])
        if shift_amount == self.description[1]:
            cp_constraints = [f'constraint {output_id_link}_active[{i}] = 0;' for i in range(shift_amount)]
            cp_constraints.extend([f'constraint {output_id_link}_active[{i}] = {all_inputs_active[i - shift_amount]};'
                                   for i in range(shift_amount, output_size // word_size)])
            cp_constraints.extend([f'constraint {output_id_link}_value[{i}] = 0;' for i in range(shift_amount)])
            cp_constraints.extend([f'constraint {output_id_link}_value[{i}] = {all_inputs_active[i - shift_amount]};'
                                   for i in range(shift_amount, output_size // word_size)])
        else:
            cp_constraints = [f'constraint {output_id_link}_active[{i}] = {all_inputs_active[i + shift_amount]};'
                              for i in range(output_size // word_size - shift_amount)]
            cp_constraints.extend([f'constraint {output_id_link}_active[{i}] = 0;'
                                   for i in
                                   range(output_size // word_size - shift_amount, output_size // word_size)])
            cp_constraints.extend([f'constraint {output_id_link}_value[{i}] = {all_inputs_active[i + shift_amount]};'
                                   for i in range(output_size // word_size - shift_amount)])
            cp_constraints.extend([f'constraint {output_id_link}_value[{i}] = 0;'
                                   for i in
                                   range(output_size // word_size - shift_amount, output_size // word_size)])

        return cp_declarations, cp_constraints

    def cp_xor_differential_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for SHIFT component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: from claasp.components.shift_component import SHIFT
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: shift_component = SHIFT(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'], [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
            sage: shift_component.cp_xor_differential_first_step_constraints(cp)
            (['array[0..3] of var 0..1: shift_0_18;'],
             ['constraint shift_0_18[0] = sbox_0_6[0];',
              'constraint shift_0_18[1] = sbox_0_10[0];',
              'constraint shift_0_18[2] = sbox_0_14[0];',
              'constraint shift_0_18[3] = 0;'])
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        shift_amount = abs(self.description[1]) // model.word_size
        all_inputs = []
        number_of_mix = 0
        is_mix = False
        numb_of_inp = len(input_id_link)
        for i in range(numb_of_inp):
            for j in range(len(input_bit_positions[i]) // model.word_size):
                all_inputs.append(
                    f'{input_id_link[i]}[{input_bit_positions[i][j * model.word_size] // model.word_size}]')
            rem = len(input_bit_positions[i]) % model.word_size
            if rem != 0:
                rem = model.word_size - (len(input_bit_positions[i]) % model.word_size)
                all_inputs.append(f'{output_id_link}_i[{number_of_mix}]')
                number_of_mix += 1
                is_mix = True
                l = 1
                while rem > 0:
                    length = len(input_bit_positions[i + l])
                    del input_bit_positions[i + l][0:rem]
                    rem -= length
                    l += 1
        cp_declarations = [f'array[0..{(output_size - 1) // model.word_size}] of var 0..1: {output_id_link};']

        if is_mix:
            cp_declarations.append(f'array[0..{number_of_mix - 1}] of var 0..1: {output_id_link}_i;')
        if shift_amount == self.description[1]:
            cp_constraints = [f'constraint {output_id_link}[{i}] = 0;' for i in range(shift_amount)]
            cp_constraints.extend([f'constraint {output_id_link}[{i}] = {all_inputs[i - shift_amount]};'
                                   for i in range(shift_amount, output_size // model.word_size)])
        else:
            cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[i + shift_amount]};'
                              for i in range(output_size // model.word_size - shift_amount)]
            cp_constraints.extend([
                f'constraint {output_id_link}[{i}] = 0;'
                for i in range(output_size // model.word_size - shift_amount, output_size // model.word_size)])

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model=None):
        return self.cp_constraints()

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        return self.cp_xor_differential_first_step_constraints(model)

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of Cp declarations and a list of Cp constraints for SHIFT component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: shift_component = tea.component_from(0, 0)
            sage: shift_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..31] of var 0..1: shift_0_0_i;',
              'array[0..31] of var 0..1: shift_0_0_o;'],
             ['constraint shift_0_0_o[0]=shift_0_0_i[4];',
              'constraint shift_0_0_o[1]=shift_0_0_i[5];',
               ...
              'constraint shift_0_0_o[27]=shift_0_0_i[31];',
              'constraint shift_0_0_i[0]=0;',
               ...
              'constraint shift_0_0_i[3]=0;'])
        """
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        shift_amount = abs(self.description[1])
        cp_constraints = []
        cp_declarations = [f'array[0..{output_size - 1}] of var 0..1: {output_id_link}_i;',
                           f'array[0..{output_size - 1}] of var 0..1: {output_id_link}_o;']
        if shift_amount == self.description[1]:
            for i in range(output_size - shift_amount, output_size):
                cp_constraints.append(f'constraint {output_id_link}_i[{i}]=0;')
            for i in range(shift_amount, output_size):
                cp_constraints.append(f'constraint {output_id_link}_o[{i}]={output_id_link}_i[{i - shift_amount}];')
        else:
            for i in range(output_size - shift_amount):
                cp_constraints.append(f'constraint {output_id_link}_o[{i}]={output_id_link}_i[{i + shift_amount}];')
            for i in range(shift_amount):
                cp_constraints.append(f'constraint {output_id_link}_i[{i}]=0;')
        result = cp_declarations, cp_constraints

        return result

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = bit_vector_SHIFT([{",".join(params)} ], {self.description[1]})']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_SHIFT({params}, {self.description[1]})']

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        shift_code = []

        self.select_words(shift_code, word_size)
        wordstring_variables.append(self.id)
        direction = "RIGHT" if self.description[1] >= 0 else "LEFT"
        shift_code.append(
            f'\tWordString *{self.id} = '
            f'{direction}_{self.description[0]}(input, {abs(self.description[1])});')

        if verbosity:
            self.print_word_values(shift_code)

        return shift_code

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        component_sign = 1
        sign = sign * component_sign
        solution['components_values'][f'{output_id_link}_o']['sign'] = component_sign
        solution['components_values'][output_id_link] = solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_i']

        return sign

    def milp_constraints(self, model):
        """
        Return a list of variables and a list of constrains modeling a component of type SHIFT for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: tea = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
            sage: milp = MilpModel(tea)
            sage: milp.init_model_in_sage_milp_class()
            sage: shift_component = tea.get_component_from_id("shift_0_0")
            sage: variables, constraints = shift_component.milp_constraints(milp)
            sage: variables
            [('x[plaintext_8]', x_0),
            ('x[plaintext_9]', x_1),
            ...
            ('x[shift_0_0_6]', x_14),
            ('x[shift_0_0_7]', x_15)]
            sage: constraints
            [x_8 == x_4,
            x_9 == x_5,
            x_10 == x_6,
            x_11 == x_7,
            x_12 == 0,
            x_13 == 0,
            x_14 == 0,
            x_15 == 0]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        shift_step = self.description[1]
        abs_shift_step = abs(shift_step)

        if shift_step < 0:
            input_vars = input_vars[abs_shift_step:] + [0] * abs_shift_step
        elif shift_step > 0:
            input_vars = [0] * abs_shift_step + input_vars[:-abs_shift_step]

        for i in range(output_bit_size):
            if input_vars[i] == 0:
                constraints.append(x[output_vars[i]] == 0)
            else:
                constraints.append(x[output_vars[i]] == x[input_vars[i]])

        return variables, constraints

    def milp_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constrains modeling a component of type Shift.

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: cipher = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: shift_component = cipher.get_component_from_id("shift_0_0")
            sage: variables, constraints = shift_component.milp_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[plaintext_8]', x_0),
            ('x_class[plaintext_9]', x_1),
            ...
            ('x_class[shift_0_0_6]', x_14),
            ('x_class[shift_0_0_7]', x_15)]
            sage: constraints
            [x_8 == x_4,
            x_9 == x_5,
            x_10 == x_6,
            x_11 == x_7,
            x_12 == 0,
            x_13 == 0,
            x_14 == 0,
            x_15 == 0]

        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        shift_step = self.description[1]
        abs_shift_step = abs(shift_step)

        if shift_step < 0:
            input_vars = input_vars[abs_shift_step:] + [0] * abs_shift_step
        elif shift_step > 0:
            input_vars = [0] * abs_shift_step + input_vars[:-abs_shift_step]

        for i in range(output_bit_size):
            if input_vars[i] == 0:
                constraints.append(x_class[output_vars[i]] == 0)
            else:
                constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constrains modeling a component of type Shift.

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'], [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
            sage: variables, constraints = shift_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[sbox_0_2_word_0_class]', x_0),
             ('x_class[sbox_0_6_word_0_class]', x_1),
             ...
             ('x[shift_0_18_30]', x_70),
             ('x[shift_0_18_31]', x_71)]
            sage: constraints
            [x_4 == x_1,
             x_5 == x_2,
             ...
             x_70 == 0,
             x_71 == 0]

        """
        x_class = model.trunc_wordvar

        input_vars, output_vars = self._get_wordwise_input_output_linked_class(model)
        class_variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        output_word_size = self.output_bit_size // model.word_size
        shift_step = self.description[1]
        abs_shift_word_step = abs(shift_step) // model.word_size

        if shift_step < 0:
            input_vars = input_vars[abs_shift_word_step:] + [0] * abs_shift_word_step
        elif shift_step > 0:
            input_vars = [0] * abs_shift_word_step + input_vars[:-abs_shift_word_step]

        for i in range(output_word_size):
            if input_vars[i] == 0:
                constraints.append(x_class[output_vars[i]] == 0)
            else:
                constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        bit_variables, bit_constraints = self.milp_constraints(model)

        return class_variables + bit_variables, constraints + bit_constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for SHIFT component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: tea = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
            sage: milp = MilpModel(tea)
            sage: milp.init_model_in_sage_milp_class()
            sage: shift_component = tea.get_component_from_id("shift_0_0")
            sage: variables, constraints = shift_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[shift_0_0_0_i]', x_0),
            ('x[shift_0_0_1_i]', x_1),
            ...
            ('x[shift_0_0_6_o]', x_14),
            ('x[shift_0_0_7_o]', x_15)]
            sage: constraints
            [x_0 == 0,
            x_1 == 0,
            x_2 == 0,
            x_3 == 0,
            x_8 == x_4,
            x_9 == x_5,
            x_10 == x_6,
            x_11 == x_7]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        shift_step = self.description[1]
        abs_shift_step = abs(shift_step)

        if shift_step < 0:
            for i in range(abs_shift_step):
                constraints.append(x[input_vars[i]] == 0)
            for i in range(output_bit_size - abs_shift_step):
                constraints.append(x[output_vars[i]] == x[input_vars[i + abs_shift_step]])
        elif shift_step > 0:
            for i in range(output_bit_size - abs_shift_step, output_bit_size):
                constraints.append(x[input_vars[i]] == 0)
            for i in range(abs_shift_step, output_bit_size):
                constraints.append(x[output_vars[i]] == x[input_vars[i - abs_shift_step]])

        return variables, constraints

    def minizinc_constraints(self, model):
        r"""
        Return variables and constraints for the component SHIFT for MINIZINC CIPHER model.

        INPUT:

        - ``model`` -- **model object**;  a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_model import MinizincModel
            sage: tea = TeaBlockCipher(number_of_rounds=32)
            sage: minizinc = MinizincModel(tea)
            sage: shift_component = tea.get_component_from_id("shift_0_0")
            sage: _, shift_mzn_constraints = shift_component.minizinc_constraints(minizinc)
            sage: shift_mzn_constraints[0]
            'constraint LSHIFT(array1d(0..32-1, [shift_0_0_x0,shift_0_0_x1,shift_0_0_x2,shift_0_0_x3,shift_0_0_x4,shift_0_0_x5,shift_0_0_x6,shift_0_0_x7,shift_0_0_x8,shift_0_0_x9,shift_0_0_x10,shift_0_0_x11,shift_0_0_x12,shift_0_0_x13,shift_0_0_x14,shift_0_0_x15,shift_0_0_x16,shift_0_0_x17,shift_0_0_x18,shift_0_0_x19,shift_0_0_x20,shift_0_0_x21,shift_0_0_x22,shift_0_0_x23,shift_0_0_x24,shift_0_0_x25,shift_0_0_x26,shift_0_0_x27,shift_0_0_x28,shift_0_0_x29,shift_0_0_x30,shift_0_0_x31]), 4)=array1d(0..32-1, [shift_0_0_y0,shift_0_0_y1,shift_0_0_y2,shift_0_0_y3,shift_0_0_y4,shift_0_0_y5,shift_0_0_y6,shift_0_0_y7,shift_0_0_y8,shift_0_0_y9,shift_0_0_y10,shift_0_0_y11,shift_0_0_y12,shift_0_0_y13,shift_0_0_y14,shift_0_0_y15,shift_0_0_y16,shift_0_0_y17,shift_0_0_y18,shift_0_0_y19,shift_0_0_y20,shift_0_0_y21,shift_0_0_y22,shift_0_0_y23,shift_0_0_y24,shift_0_0_y25,shift_0_0_y26,shift_0_0_y27,shift_0_0_y28,shift_0_0_y29,shift_0_0_y30,shift_0_0_y31]);\n'
        """
        var_names = self._define_var(model.input_postfix, model.output_postfix, model.data_type)
        shift_const = self.description[1]
        ninputs = noutputs = self.output_bit_size
        input_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        input_vars_1 = input_vars
        mzn_input_array_1 = self._create_minizinc_1d_array_from_list(input_vars_1)
        output_vars_1 = output_vars
        mzn_output_array_1 = self._create_minizinc_1d_array_from_list(output_vars_1)

        if shift_const < 0:
            shift_mzn_constraints = [
                f'constraint LSHIFT({mzn_input_array_1}, {int(-1*shift_const)})={mzn_output_array_1};\n']
        else:
            shift_mzn_constraints = [
                f'constraint RSHIFT({mzn_input_array_1}, {int(shift_const)})={mzn_output_array_1};\n']

        return var_names, shift_mzn_constraints

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.minizinc_constraints(model)

    def minizinc_xor_differential_propagation_constraints(self, model):
        return self.minizinc_constraints(model)

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for SHIFT in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: shift_component = tea.component_from(0, 0)
            sage: shift_component.sat_constraints()
            (['shift_0_0_0',
              'shift_0_0_1',
              'shift_0_0_2',
              ...
              '-shift_0_0_29',
              '-shift_0_0_30',
              '-shift_0_0_31'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            for i in range(output_bit_len - shift_amount):
                constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i + shift_amount]]))
            for i in range(output_bit_len - shift_amount, output_bit_len):
                constraints.append(f'-{output_bit_ids[i]}')
        else:
            for i in range(shift_amount):
                constraints.append(f'-{output_bit_ids[i]}')
            for i in range(shift_amount, output_bit_len):
                constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i - shift_amount]]))

        return output_bit_ids, constraints

    def sat_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.sat_constraints()

    def sat_xor_differential_propagation_constraints(self, model=None):
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for SHIFT in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: shift_component = tea.component_from(0, 0)
            sage: shift_component.sat_xor_linear_mask_propagation_constraints()
            (['shift_0_0_0_i',
              'shift_0_0_1_i',
              'shift_0_0_2_i',
              ...
              'shift_0_0_30_i -shift_0_0_26_o',
              'shift_0_0_27_o -shift_0_0_31_i',
              'shift_0_0_31_i -shift_0_0_27_o'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            constraints.extend([f'-{input_bit_ids[i]}' for i in range(shift_amount)])
            for i in range(output_bit_len - shift_amount):
                constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i + shift_amount]]))
        else:
            for i in range(shift_amount, output_bit_len):
                constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i - shift_amount]]))
            constraints.extend([f'-{input_bit_ids[i]}'
                                for i in range(output_bit_len - shift_amount, output_bit_len)])
        result = input_bit_ids + output_bit_ids, constraints

        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing for SMT CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: shift_component = tea.component_from(0, 0)
            sage: shift_component.smt_constraints()
            (['shift_0_0_0',
              'shift_0_0_1',
              ...
              'shift_0_0_30',
              'shift_0_0_31'],
             ['(assert (= shift_0_0_0 plaintext_36))',
              '(assert (= shift_0_0_1 plaintext_37))',
              ...
              '(assert (= shift_0_0_27 plaintext_63))',
              '(assert (not shift_0_0_28))',
              '(assert (not shift_0_0_29))',
              '(assert (not shift_0_0_30))',
              '(assert (not shift_0_0_31))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            for i in range(output_bit_len - shift_amount):
                equation = smt_utils.smt_equivalent((output_bit_ids[i], input_bit_ids[i + shift_amount]))
                constraints.append(smt_utils.smt_assert(equation))
            for i in range(output_bit_len - shift_amount, output_bit_len):
                constraints.append(smt_utils.smt_assert(smt_utils.smt_not(output_bit_ids[i])))
        else:
            for i in range(shift_amount):
                constraints.append(smt_utils.smt_assert(smt_utils.smt_not(output_bit_ids[i])))
            for i in range(shift_amount, output_bit_len):
                equation = smt_utils.smt_equivalent((output_bit_ids[i], input_bit_ids[i - shift_amount]))
                constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.smt_constraints()

    def smt_xor_differential_propagation_constraints(self, model=None):
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for SHIFT in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: shift_component = tea.component_from(0, 0)
            sage: shift_component.smt_xor_linear_mask_propagation_constraints()
            (['shift_0_0_0_i',
              'shift_0_0_1_i',
              ...
              'shift_0_0_30_o',
              'shift_0_0_31_o'],
             ['(assert (not shift_0_0_0_i))',
              '(assert (not shift_0_0_1_i))',
              ...
              '(assert (= shift_0_0_26_o shift_0_0_30_i))',
              '(assert (= shift_0_0_27_o shift_0_0_31_i))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            constraints.extend([smt_utils.smt_assert(smt_utils.smt_not(input_bit_ids[i]))
                                for i in range(shift_amount)])
            for i in range(output_bit_len - shift_amount):
                equation = smt_utils.smt_equivalent((output_bit_ids[i], input_bit_ids[i + shift_amount]))
                constraints.append(smt_utils.smt_assert(equation))
        else:
            for i in range(shift_amount, output_bit_len):
                equation = smt_utils.smt_equivalent((output_bit_ids[i], input_bit_ids[i - shift_amount]))
                constraints.append(smt_utils.smt_assert(equation))
            constraints.extend([smt_utils.smt_assert(smt_utils.smt_not(input_bit_ids[i]))
                                for i in range(output_bit_len - shift_amount, output_bit_len)])
        result = input_bit_ids + output_bit_ids, constraints

        return result
