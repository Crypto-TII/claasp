
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


class Rotate(Component):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, parameter):
        component_id = f'rot_{current_round_number}_{current_round_number_of_components}'
        component_type = 'word_operation'
        description = ['ROTATE', parameter]
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for bitwise ROTATION.

        INPUT:

        - ``model`` --  **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: rotate_component = fancy.get_component_from_id("rot_1_11")
            sage: algebraic = AlgebraicModel(fancy)
            sage: rotate_component.algebraic_polynomials(algebraic)
            [rot_1_11_y0 + rot_1_11_x3,
             rot_1_11_y1 + rot_1_11_x4,
             rot_1_11_y2 + rot_1_11_x5,
             rot_1_11_y3 + rot_1_11_x0,
             rot_1_11_y4 + rot_1_11_x1,
             rot_1_11_y5 + rot_1_11_x2]
        """
        if self.description[0].lower() != "rotate":
            raise ValueError("component must be bitwise rotation")

        rotation_const = self.description[1]
        ninputs = noutputs = self.output_bit_size
        input_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        ring_R = model.ring()
        x = list(map(ring_R, input_vars))
        y = list(map(ring_R, output_vars))
        polynomials = [y[i] + x[(rotation_const + i) % noutputs] for i in range(noutputs)]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for ROTATION in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: rotate_component = speck.component_from(1, 1)
            sage: rotate_component.cms_constraints()
            (['rot_1_1_0',
              'rot_1_1_1',
              'rot_1_1_2',
              ...
              'key_39 -rot_1_1_14',
              'rot_1_1_15 -key_40',
              'key_40 -rot_1_1_15'])
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
        Return lists of declarations and constraints for ROTATE component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: rotate_component = speck.component_from(0, 0)
            sage: rotate_component.cp_constraints()
            ([],
             ['constraint rot_0_0[0] = plaintext[9];',
              ...
              'constraint rot_0_0[15] = plaintext[8];'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        rot_amount = abs(self.description[1])
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_declarations = []
        input_len = len(all_inputs)
        if rot_amount == self.description[1]:
            cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[(i - rot_amount) % input_len]};'
                              for i in range(output_size)]
        else:
            cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[(i + rot_amount) % input_len]};'
                              for i in range(output_size)]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_constraints()

    def cp_inverse_constraints(self):
        """
        Return lists of declarations and constraints for ROTATE component for CP INVERSE CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: rotate_component = speck.component_from(0, 0)
            sage: rotate_component.cp_inverse_constraints()
            ([],
             ['constraint rot_0_0_inverse[0] = plaintext[9];',
              ...
              'constraint rot_0_0_inverse[15] = plaintext[8];'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        rot_amount = abs(self.description[1])
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_declarations = []
        input_len = len(all_inputs)
        if rot_amount == self.description[1]:
            cp_constraints = [f'constraint {output_id_link}_inverse[{i}] = {all_inputs[(i - rot_amount) % input_len]};'
                              for i in range(output_size)]
        else:
            cp_constraints = [f'constraint {output_id_link}_inverse[{i}] = {all_inputs[(i + rot_amount) % input_len]};'
                              for i in range(output_size)]

        return cp_declarations, cp_constraints

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists of declarations and constraints for ROTATE CP deterministic truncated xor differential model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: rotate_component = aes.component_from(0, 18)
            sage: rotate_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)
            ([],
             ['constraint rot_0_18[0]_active = sbox_0_6_active[0];',
              'constraint rot_0_18[1]_active = sbox_0_10_active[0];',
                ...
              'constraint rot_0_18[2]_value = sbox_0_14_value[0];',
              'constraint rot_0_18[3]_value = sbox_0_2_value[0];'])
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        word_size = model.word_size
        rot_amount = abs(self.description[1]) // word_size
        all_inputs_active = []
        all_inputs_value = []
        cp_declarations = []
        for id_link, bit_positions in zip(input_id_link, input_bit_positions):
            all_inputs_active.extend([f'{id_link}_active[{bit_positions[j * word_size] // word_size}]'
                                      for j in range(len(bit_positions) // word_size)])
        for id_link, bit_positions in zip(input_id_link, input_bit_positions):
            all_inputs_value.extend([f'{id_link}_value[{bit_positions[j * word_size] // word_size}]'
                                     for j in range(len(bit_positions) // word_size)])
        input_len = len(all_inputs_active)

        if rot_amount == self.description[1]:
            cp_constraints = [
                f'constraint {output_id_link}[{i}]_active = {all_inputs_active[(i - rot_amount) % input_len]};'
                for i in range(output_size // word_size)]
            cp_constraints.extend([
                f'constraint {output_id_link}[{j}]_value = {all_inputs_value[(j - rot_amount) % input_len]};' for j in
                range(output_size // word_size)])
        else:
            cp_constraints = [
                f'constraint {output_id_link}[{i}]_active = {all_inputs_active[(i + rot_amount) % input_len]};'
                for i in range(output_size // word_size)]
            cp_constraints.extend([
                f'constraint {output_id_link}[{j}]_value = {all_inputs_value[(j + rot_amount) % input_len]};' for j in
                range(output_size // word_size)])

        return cp_declarations, cp_constraints

    def cp_xor_differential_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for ROTATE component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: rotate_component = aes.component_from(0, 18)
            sage: rotate_component.cp_xor_differential_first_step_constraints(cp)
            (['array[0..3] of var 0..1: rot_0_18;'],
             ['constraint rot_0_18[0] = sbox_0_6[0];',
              'constraint rot_0_18[1] = sbox_0_10[0];',
              'constraint rot_0_18[2] = sbox_0_14[0];',
              'constraint rot_0_18[3] = sbox_0_2[0];'])
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        word_size = model.word_size
        rot_amount = abs(self.description[1]) // word_size
        numb_of_inp = len(input_id_link)
        all_inputs = []
        number_of_mix = 0
        is_mix = False
        for i in range(numb_of_inp):
            for j in range(len(input_bit_positions[i]) // word_size):
                all_inputs.append(f'{input_id_link[i]}[{input_bit_positions[i][j * word_size] // word_size}]')
            rem = len(input_bit_positions[i]) % word_size
            if rem != 0:
                rem = word_size - (len(input_bit_positions[i]) % word_size)
                all_inputs.append(f'{output_id_link}_i[{number_of_mix}]')
                number_of_mix += 1
                is_mix = True
                l = 1
                while rem > 0:
                    length = len(input_bit_positions[i + l])
                    del input_bit_positions[i + l][0:rem]
                    rem -= length
                    l += 1
        cp_declarations = [f'array[0..{(output_size - 1) // word_size}] of var 0..1: {output_id_link};']
        if is_mix:
            cp_declarations.append(f'array[0..{number_of_mix - 1}] of var 0..1: {output_id_link}_i;')
        input_len = len(all_inputs)
        if rot_amount == self.description[1]:
            cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[(i - rot_amount) % input_len]};'
                              for i in range(output_size // word_size)]
        else:
            cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[(i + rot_amount) % input_len]};'
                              for i in range(output_size // word_size)]

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model=None):
        return self.cp_constraints()

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        return self.cp_xor_differential_first_step_constraints(model)

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for ROTATE component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: rotate_component = speck.component_from(0, 0)
            sage: rotate_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..15] of var 0..1: rot_0_0_i;',
              'array[0..15] of var 0..1: rot_0_0_o;'],
             ['constraint rot_0_0_o[0]=rot_0_0_i[9];',
              ...
              'constraint rot_0_0_o[15]=rot_0_0_i[8];'])
        """
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        rot_amount = abs(self.description[1])
        cp_constraints = []
        cp_declarations = [f'array[0..{output_size - 1}] of var 0..1: {output_id_link}_i;',
                           f'array[0..{output_size - 1}] of var 0..1: {output_id_link}_o;']
        if rot_amount == self.description[1]:
            for i in range(output_size):
                cp_constraints.append(
                    f'constraint {output_id_link}_o[{i}]={output_id_link}_i[{(i - rot_amount) % output_size}];')
        else:
            for i in range(output_size):
                cp_constraints.append(
                    f'constraint {output_id_link}_o[{i}]={output_id_link}_i[{(i + rot_amount) % output_size}];')
        result = cp_declarations, cp_constraints

        return result

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = bit_vector_ROTATE([{",".join(params)} ], {self.description[1]})']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_ROTATE({params}, {self.description[1]})']

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        rotate_code = []

        self.select_words(rotate_code, word_size)
        wordstring_variables.append(self.id)
        direction = "RIGHT" if self.description[1] >= 0 else "LEFT"
        rotate_code.append(
            f'\tWordString *{self.id} = '
            f'{direction}_{self.description[0]}(input, {abs(self.description[1])});')

        if verbosity:
            self.print_word_values(rotate_code)

        return rotate_code

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
        Return a list of variables and a list of constrains modeling a component of type ROTATE for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: rotate_component = speck.get_component_from_id("rot_1_1")
            sage: variables, constraints = rotate_component.milp_constraints(milp)
            sage: variables
            [('x[key_32]', x_0),
            ('x[key_33]', x_1),
            ...
            ('x[rot_1_1_14]', x_30),
            ('x[rot_1_1_15]', x_31)]
            sage: constraints
            [x_16 == x_9,
            x_17 == x_10,
            ...
            x_30 == x_7,
            x_31 == x_8]
        """
        x = model.binary_variable
        output_bit_size = self.output_bit_size
        rotation_step = self.description[1]
        abs_rotation_step = abs(rotation_step)
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []

        if rotation_step < 0:
            tmp = input_vars[:abs_rotation_step]
            input_vars = input_vars[abs_rotation_step:] + tmp
        elif rotation_step > 0:
            tmp = input_vars[-abs_rotation_step:]
            input_vars = tmp + input_vars[:-abs_rotation_step]
        for i in range(output_bit_size):
            constraints.append(x[output_vars[i]] == x[input_vars[i]])

        return variables, constraints

    def milp_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for ROTATE operation in MILP XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: rotate_component = speck.get_component_from_id("rot_1_1")
            sage: variables, constraints = rotate_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
             [('x[rot_1_1_0_i]', x_0),
             ('x[rot_1_1_1_i]', x_1),
             ...
             ('x[rot_1_1_14_o]', x_30),
             ('x[rot_1_1_15_o]', x_31)]
            sage: constraints
            [x_16 == x_9,
            x_17 == x_10,
            ...
            x_30 == x_7,
            x_31 == x_8]
        """
        x = model.binary_variable
        output_bit_size = self.output_bit_size
        rotation_step = self.description[1]
        abs_rotation_step = abs(rotation_step)
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        if rotation_step < 0:
            tmp = input_vars[:abs_rotation_step]
            input_vars = input_vars[abs_rotation_step:] + tmp
        elif rotation_step > 0:
            tmp = input_vars[-abs_rotation_step:]
            input_vars = tmp + input_vars[:-abs_rotation_step]
        for i in range(output_bit_size):
            constraints.append(x[output_vars[i]] == x[input_vars[i]])
        result = variables, constraints

        return result

    def minizinc_constraints(self, model):
        r"""
        Return variables and constraints for the component ROTATE for MINIZINC CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_model import MinizincModel
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: minizinc = MinizincModel(fancy)
            sage: rotate_component = fancy.get_component_from_id("rot_1_11")
            sage: _, rotate_mzn_constraints = rotate_component.minizinc_constraints(minizinc)
            sage: rotate_mzn_constraints[0]
            'constraint LRot(array1d(0..6-1, [rot_1_11_x0,rot_1_11_x1,rot_1_11_x2,rot_1_11_x3,rot_1_11_x4,rot_1_11_x5]), 3)=array1d(0..6-1, [rot_1_11_y0,rot_1_11_y1,rot_1_11_y2,rot_1_11_y3,rot_1_11_y4,rot_1_11_y5]);\n'
        """
        if self.description[0].lower() != "rotate":
            raise ValueError("component must be bitwise rotation")
        input_postfix = model.input_postfix
        output_postfix = model.output_postfix

        var_names = self._define_var(input_postfix, output_postfix, model.data_type)
        rotation_const = self.description[1]
        ninputs = noutputs = self.output_bit_size
        input_vars = [self.id + "_" + input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + "_" + output_postfix + str(i) for i in range(noutputs)]
        input_vars_1 = input_vars
        mzn_input_array_1 = self._create_minizinc_1d_array_from_list(input_vars_1)
        output_vars_1 = output_vars
        mzn_output_array_1 = self._create_minizinc_1d_array_from_list(output_vars_1)

        if rotation_const < 0:
            rotate_mzn_constraints = [
                f'constraint LRot({mzn_input_array_1}, {int(-1*rotation_const)})={mzn_output_array_1};\n']
        else:
            rotate_mzn_constraints = [
                f'constraint RRot({mzn_input_array_1}, {int(rotation_const)})={mzn_output_array_1};\n']

        return var_names, rotate_mzn_constraints

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.minizinc_constraints(model)

    def minizinc_xor_differential_propagation_constraints(self, model):
        return self.minizinc_constraints(model)

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for ROTATION in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: rotate_component = speck.component_from(1, 1)
            sage: rotate_component.sat_constraints()
            (['rot_1_1_0',
              'rot_1_1_1',
              'rot_1_1_2',
              ...
              'key_39 -rot_1_1_14',
              'rot_1_1_15 -key_40',
              'key_40 -rot_1_1_15'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        rotation = self.description[1]
        input_bit_ids_rotated = input_bit_ids[-rotation:] + input_bit_ids[:-rotation]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids_rotated[i]]))

        return output_bit_ids, constraints

    def sat_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.sat_constraints()

    def sat_xor_differential_propagation_constraints(self, model=None):
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for ROTATION in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: rotate_component = speck.component_from(1, 1)
            sage: rotate_component.sat_xor_linear_mask_propagation_constraints()
            (['rot_1_1_0_i',
              'rot_1_1_1_i',
              'rot_1_1_2_i',
              ...
              'rot_1_1_7_i -rot_1_1_14_o',
              'rot_1_1_15_o -rot_1_1_8_i',
              'rot_1_1_8_i -rot_1_1_15_o'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(out_suffix)
        rotation = self.description[1]
        input_bit_ids_rotated = input_bit_ids[-rotation:] + input_bit_ids[:-rotation]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids_rotated[i]]))
        result = input_bit_ids + output_bit_ids, constraints

        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing ROTATION for SMT CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: rotate_component = speck.component_from(0, 0)
            sage: rotate_component.smt_constraints()
            (['rot_0_0_0',
              'rot_0_0_1',
              ...
              'rot_0_0_14',
              'rot_0_0_15'],
             ['(assert (= rot_0_0_0 plaintext_9))',
              '(assert (= rot_0_0_1 plaintext_10))',
              ...
              '(assert (= rot_0_0_14 plaintext_7))',
              '(assert (= rot_0_0_15 plaintext_8))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        rotation = self.description[1]
        input_bit_ids_rotated = input_bit_ids[-rotation:] + input_bit_ids[:-rotation]
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids_rotated[i]])
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.smt_constraints()

    def smt_xor_differential_propagation_constraints(self, model=None):
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for rotate in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: rotate_component = speck.component_from(0, 0)
            sage: rotate_component.smt_xor_linear_mask_propagation_constraints()
            (['rot_0_0_0_i',
              'rot_0_0_1_i',
              ...
              'rot_0_0_14_o',
              'rot_0_0_15_o'],
             ['(assert (= rot_0_0_0_o rot_0_0_9_i))',
              '(assert (= rot_0_0_1_o rot_0_0_10_i))',
              ...
              '(assert (= rot_0_0_14_o rot_0_0_7_i))',
              '(assert (= rot_0_0_15_o rot_0_0_8_i))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(out_suffix)
        rotation = self.description[1]
        input_bit_ids_rotated = input_bit_ids[-rotation:] + input_bit_ids[:-rotation]
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids_rotated[i]])
            constraints.append(smt_utils.smt_assert(equation))
        result = input_bit_ids + output_bit_ids, constraints

        return result
