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


from sage.matrix.constructor import Matrix
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import FiniteField

from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import \
    update_dictionary_that_contains_xor_inequalities_for_specific_wordwise_matrix, \
    output_dictionary_that_contains_wordwise_truncated_xor_inequalities
from claasp.cipher_modules.models.milp.utils.utils import espresso_pos_to_constraints
from claasp.input import Input
from claasp.component import Component, free_input
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.sat.utils import constants, utils as sat_utils
from claasp.cipher_modules.models.milp.utils import utils as milp_utils
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_xor_with_n_input_bits import (
    update_dictionary_that_contains_xor_inequalities_for_specific_matrix,
    output_dictionary_that_contains_xor_inequalities)


def update_constraints_for_more_than_one_bit(constraints, dict_inequalities, i, indexes_of_values_in_col, input_vars,
                                             number_of_1s, output_vars, x):
    inequalities = dict_inequalities[number_of_1s]
    for ineq in inequalities:
        index_ineq = 0
        tmp = 0
        for value_index in indexes_of_values_in_col:
            char = ineq[index_ineq]
            if char == "1":
                tmp += 1 - x[input_vars[value_index]]
                index_ineq += 1
            elif char == "0":
                tmp += x[input_vars[value_index]]
                index_ineq += 1
        char = ineq[index_ineq]
        if char == "1":
            tmp += 1 - x[output_vars[i]]
            constraints.append(tmp >= 1)
        elif char == "0":
            tmp += x[output_vars[i]]
            constraints.append(tmp >= 1)


class LinearLayer(Component):
    def __init__(self, current_round_number, current_round_number_of_components, input_id_links,
                 input_bit_positions, output_bit_size, description):
        component_id = f'linear_layer_{current_round_number}_{current_round_number_of_components}'
        component_type = 'linear_layer'
        input_len = 0
        for bits in input_bit_positions:
            input_len = input_len + len(bits)
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for LINEAR LAYER.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: linear_layer_component = fancy.get_component_from_id("linear_layer_0_6")
            sage: algebraic = AlgebraicModel(fancy)
            sage: L = linear_layer_component.algebraic_polynomials(algebraic)
            sage: L[0]
            linear_layer_0_6_y0 + linear_layer_0_6_x23 + linear_layer_0_6_x19 + linear_layer_0_6_x18 + linear_layer_0_6_x16 + linear_layer_0_6_x15 + linear_layer_0_6_x14 + linear_layer_0_6_x12 + linear_layer_0_6_x9 + linear_layer_0_6_x8 + linear_layer_0_6_x6 + linear_layer_0_6_x3
        """
        noutputs = self.output_bit_size
        ninputs = self.input_bit_size
        ring_R = model.ring()
        M = Matrix(ring_R, self.description, nrows=noutputs, ncols=ninputs)
        x = vector(ring_R, (map(ring_R, [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)])))
        y = vector(ring_R,
                   list(map(ring_R, [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)])))

        return (y - M * x).list()

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for LINEAR LAYER in CMS CIPHER model.

        .. SEEALSO::

            :ref:`CMS CIPHER model  <cms-cipher-standard>` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0,6)
            sage: linear_layer_component.cms_constraints()
            (['linear_layer_0_6_0',
              'linear_layer_0_6_1',
              'linear_layer_0_6_2',
              ...
              'x -linear_layer_0_6_21 sbox_0_0_1 sbox_0_1_2 sbox_0_1_3 sbox_0_2_0 sbox_0_2_1 sbox_0_2_3 sbox_0_3_1 sbox_0_3_2 sbox_0_4_1 sbox_0_4_2 sbox_0_5_1 sbox_0_5_3',
              'x -linear_layer_0_6_22 sbox_0_0_2 sbox_0_2_2 sbox_0_3_2 sbox_0_4_3 sbox_0_5_0 sbox_0_5_1 sbox_0_5_3',
              'x -linear_layer_0_6_23 sbox_0_0_0 sbox_0_0_1 sbox_0_0_2 sbox_0_0_3 sbox_0_1_3 sbox_0_2_1 sbox_0_3_1 sbox_0_3_2 sbox_0_3_3 sbox_0_4_1 sbox_0_4_2 sbox_0_4_3 sbox_0_5_1 sbox_0_5_2 sbox_0_5_3'])
        """
        input_bit_len, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        matrix = self.description
        constraints = []
        for i in range(output_bit_len):
            operands = [f'x -{output_bit_ids[i]}']
            operands.extend(input_bit_ids[j] for j in range(input_bit_len) if matrix[j][i])
            constraints.append(' '.join(operands))

        return output_bit_ids, constraints

    def cms_xor_differential_propagation_constraints(self, model):
        return self.cms_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for LINEAR LAYER in CMS XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0,6)
            sage: linear_layer_component.cms_xor_linear_mask_propagation_constraints()
            (['linear_layer_0_6_0_i',
              'linear_layer_0_6_1_i',
              'linear_layer_0_6_2_i',
              ...
              'x -linear_layer_0_6_21_o dummy_0_linear_layer_0_6_21_o dummy_1_linear_layer_0_6_21_o dummy_2_linear_layer_0_6_21_o dummy_3_linear_layer_0_6_21_o dummy_4_linear_layer_0_6_21_o dummy_5_linear_layer_0_6_21_o dummy_6_linear_layer_0_6_21_o dummy_8_linear_layer_0_6_21_o dummy_9_linear_layer_0_6_21_o dummy_10_linear_layer_0_6_21_o dummy_11_linear_layer_0_6_21_o dummy_12_linear_layer_0_6_21_o dummy_18_linear_layer_0_6_21_o dummy_19_linear_layer_0_6_21_o dummy_23_linear_layer_0_6_21_o',
              'x -linear_layer_0_6_22_o dummy_0_linear_layer_0_6_22_o dummy_1_linear_layer_0_6_22_o dummy_2_linear_layer_0_6_22_o dummy_3_linear_layer_0_6_22_o dummy_4_linear_layer_0_6_22_o dummy_6_linear_layer_0_6_22_o dummy_9_linear_layer_0_6_22_o dummy_13_linear_layer_0_6_22_o dummy_14_linear_layer_0_6_22_o dummy_15_linear_layer_0_6_22_o dummy_16_linear_layer_0_6_22_o dummy_19_linear_layer_0_6_22_o dummy_20_linear_layer_0_6_22_o dummy_21_linear_layer_0_6_22_o',
              'x -linear_layer_0_6_23_o dummy_1_linear_layer_0_6_23_o dummy_5_linear_layer_0_6_23_o dummy_7_linear_layer_0_6_23_o dummy_8_linear_layer_0_6_23_o dummy_9_linear_layer_0_6_23_o dummy_14_linear_layer_0_6_23_o dummy_17_linear_layer_0_6_23_o dummy_18_linear_layer_0_6_23_o dummy_23_linear_layer_0_6_23_o'])
        """
        input_bit_len, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        inverse_matrix = Matrix(FiniteField(2), self.description).inverse()
        dummy_variables = [[] for _ in range(output_bit_len)]
        constraints = []
        for i in range(input_bit_len):
            operands = [input_bit_ids[i]]
            for j in range(output_bit_len):
                if inverse_matrix[j][i]:
                    variable = f'dummy_{i}_{output_bit_ids[j]}'
                    operands.append(variable)
                    dummy_variables[j].append(variable)
            constraints.extend(sat_utils.cnf_equivalent(operands))
        for i in range(output_bit_len):
            operands = [f'x -{output_bit_ids[i]}'] + dummy_variables[i]
            constraints.append(' '.join(operands))
        dummy_bit_ids = [d for i in range(output_bit_len) for d in dummy_variables[i]]

        return input_bit_ids + dummy_bit_ids + output_bit_ids, constraints

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for LINEAR LAYER component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0, 6)
            sage: linear_layer_component.cp_constraints()
            ([],
             ['constraint linear_layer_0_6[0] = (sbox_0_0[2] + sbox_0_0[3] + sbox_0_1[0] + sbox_0_1[1] + sbox_0_1[3] + sbox_0_2[0] + sbox_0_2[1] + sbox_0_3[1] + sbox_0_4[2] + sbox_0_5[1] + sbox_0_5[3]) mod 2;',
              ...
              'constraint linear_layer_0_6[23] = (sbox_0_0[0] + sbox_0_0[1] + sbox_0_0[2] + sbox_0_0[3] + sbox_0_1[3] + sbox_0_2[1] + sbox_0_3[1] + sbox_0_3[2] + sbox_0_3[3] + sbox_0_4[1] + sbox_0_4[2] + sbox_0_4[3] + sbox_0_5[1] + sbox_0_5[2] + sbox_0_5[3]) mod 2;'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        matrix = self.description
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = []
        for i in range(output_size):
            addenda = [all_inputs[j] for j in range(len(matrix)) if matrix[j][i]]
            sum_of_addenda = ' + '.join(addenda)
            new_constraint = f'constraint {output_id_link}[{i}] = ({sum_of_addenda}) mod 2;'
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_constraints(self, inverse=False):
        r"""
        Return lists declarations and constraints for LINEAR LAYER CP deterministic truncated xor differential model.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0, 6)
            sage: linear_layer_component.cp_deterministic_truncated_xor_differential_constraints()
            ([],
             ['constraint if ((sbox_0_0[2] < 2) /\\ (sbox_0_0[3] < 2) /\\ (sbox_0_1[0] < 2) /\\ (sbox_0_1[1] < 2) /\\ (sbox_0_1[3] < 2) /\\ (sbox_0_2[0] < 2) /\\ (sbox_0_2[1] < 2) /\\ (sbox_0_3[1] < 2) /\\ (sbox_0_4[2] < 2) /\\ (sbox_0_5[1] < 2) /\\ (sbox_0_5[3]< 2)) then linear_layer_0_6[0] = (sbox_0_0[2] + sbox_0_0[3] + sbox_0_1[0] + sbox_0_1[1] + sbox_0_1[3] + sbox_0_2[0] + sbox_0_2[1] + sbox_0_3[1] + sbox_0_4[2] + sbox_0_5[1] + sbox_0_5[3]) mod 2 else linear_layer_0_6[0] = 2 endif;',
              ...
              'constraint if ((sbox_0_0[0] < 2) /\\ (sbox_0_0[1] < 2) /\\ (sbox_0_0[2] < 2) /\\ (sbox_0_0[3] < 2) /\\ (sbox_0_1[3] < 2) /\\ (sbox_0_2[1] < 2) /\\ (sbox_0_3[1] < 2) /\\ (sbox_0_3[2] < 2) /\\ (sbox_0_3[3] < 2) /\\ (sbox_0_4[1] < 2) /\\ (sbox_0_4[2] < 2) /\\ (sbox_0_4[3] < 2) /\\ (sbox_0_5[1] < 2) /\\ (sbox_0_5[2] < 2) /\\ (sbox_0_5[3]< 2)) then linear_layer_0_6[23] = (sbox_0_0[0] + sbox_0_0[1] + sbox_0_0[2] + sbox_0_0[3] + sbox_0_1[3] + sbox_0_2[1] + sbox_0_3[1] + sbox_0_3[2] + sbox_0_3[3] + sbox_0_4[1] + sbox_0_4[2] + sbox_0_4[3] + sbox_0_5[1] + sbox_0_5[2] + sbox_0_5[3]) mod 2 else linear_layer_0_6[23] = 2 endif;'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        matrix = self.description
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
            addenda = [all_inputs[j] for j in range(len(matrix)) if matrix[j][i]]
            operation = f' < 2) /\\ ('.join(addenda)
            new_constraint = f'constraint if (('
            new_constraint += operation + f'< 2)) then '
            operation2 = ' + '.join(addenda)
            if inverse:
                new_constraint += f'{output_id_link}_inverse[{i}] = ({operation2}) mod 2 ' \
                                  f'else {output_id_link}_inverse[{i}] = 2 endif;'
            else:
                new_constraint += f'{output_id_link}[{i}] = ({operation2}) mod 2 else {output_id_link}[{i}] = 2 endif;'
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_xor_differential_propagation_constraints(self, model):
        return self.cp_constraints()

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for LINEAR LAYER for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher()
            sage: linear_layer_component = fancy.component_from(0, 6)
            sage: linear_layer_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..23] of var 0..1:linear_layer_0_6_i;',
            'array[0..23] of var 0..1:linear_layer_0_6_o;'],
            ['constraint linear_layer_0_6_i[0]=(linear_layer_0_6_o[3]+linear_layer_0_6_o[6]+linear_layer_0_6_o[8]+linear_layer_0_6_o[9]+linear_layer_0_6_o[12]+linear_layer_0_6_o[14]+linear_layer_0_6_o[15]+linear_layer_0_6_o[16]+linear_layer_0_6_o[18]+linear_layer_0_6_o[19]+linear_layer_0_6_o[23]) mod 2;',
            ...
            'constraint linear_layer_0_6_i[23]=(linear_layer_0_6_o[0]+linear_layer_0_6_o[1]+linear_layer_0_6_o[2]+linear_layer_0_6_o[3]+linear_layer_0_6_o[4]+linear_layer_0_6_o[7]+linear_layer_0_6_o[8]+linear_layer_0_6_o[11]+linear_layer_0_6_o[13]+linear_layer_0_6_o[14]+linear_layer_0_6_o[15]+linear_layer_0_6_o[18]+linear_layer_0_6_o[19]+linear_layer_0_6_o[20]+linear_layer_0_6_o[21]+linear_layer_0_6_o[22]+linear_layer_0_6_o[23]) mod 2;'])
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        description = self.description
        cp_declarations = []
        cp_constraints = []
        matrix = Matrix(FiniteField(2), description)
        cp_declarations.append(f'array[0..{input_size - 1}] of var 0..1:{output_id_link}_i;')
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1:{output_id_link}_o;')
        for i in range(input_size):
            new_constraint = f'constraint {output_id_link}_i[{i}]=('
            for j in range(input_size):
                if matrix[i][j] == 1:
                    new_constraint = new_constraint + f'{output_id_link}_o[{j}]+'
            new_constraint = new_constraint[:-1] + f') mod 2;'
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def get_bit_based_cuda_code(self, verbosity):
        linear_layer_code = []
        self.select_bits_cuda(linear_layer_code)
        len_description_list = len(self.description)
        linear_layer_code.append(f'\tlinear_transformation = new uint8_t*[{len_description_list}];\n')

        for k, row in enumerate(self.description):
            linear_layer_code.append(f'\tlinear_transformation[{k}] = new uint8_t[{len_description_list}] {{{", ".join([str(x) for x in row])}}};')

        linear_layer_code.append(f'\tBitString* {self.id} = LINEAR_LAYER(input, linear_transformation);\n')

        if verbosity:
            self.print_values(linear_layer_code)

        free_input(linear_layer_code)

        for k, position_list in enumerate(self.input_bit_positions):
            linear_layer_code.append(f'\tdelete [] linear_transformation[{k}];')
        linear_layer_code.append(f'\tdelete [] linear_transformation;')

        return linear_layer_code

    def get_bit_based_c_code(self, verbosity):
        linear_layer_code = []
        self.select_bits(linear_layer_code)

        linear_layer_code.append('\tlinear_transformation = (uint8_t*[]) {')
        for row in self.description:
            linear_layer_code.append(f'\t\t(uint8_t[]) {{{", ".join([str(x) for x in row])}}},')
        linear_layer_code.append('\t};')

        linear_layer_code.append(f'\tBitString* {self.id} = LINEAR_LAYER(input, linear_transformation);\n')

        if verbosity:
            self.print_values(linear_layer_code)

        free_input(linear_layer_code)

        return linear_layer_code

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = bit_vector_linear_layer(bit_vector_CONCAT([{",".join(params)} ]), {self.description})']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_linear_layer({params}, {self.description})']

    def milp_constraints(self, model):
        """
        Return lists of variables and constrains modeling a component of type LINEAR LAYER for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: present = PresentBlockCipher(number_of_rounds=6)
            sage: milp = MilpModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: linear_layer_component = present.component_from(0, 17)
            sage: variables, constraints = linear_layer_component.milp_constraints(milp) # long
            sage: variables # long
            [('x[sbox_0_1_0]', x_0),
            ('x[sbox_0_1_1]', x_1),
            ...
            ('x[linear_layer_0_17_62]', x_126),
            ('x[linear_layer_0_17_63]', x_127)]
            sage: constraints # long
            [x_64 == x_0,
            x_65 == x_4,
            ...
            x_126 == x_59,
            x_127 == x_63]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        matrix = self.description

        dict_inequalities = {}
        matrix_without_unit_vectors = [row for row in matrix if sum([int(i) for i in row]) > 1]
        if matrix_without_unit_vectors:
            update_dictionary_that_contains_xor_inequalities_for_specific_matrix(matrix_without_unit_vectors)
            dict_inequalities = output_dictionary_that_contains_xor_inequalities()

        for i in range(len(matrix)):
            col = [row[i] for row in matrix]
            number_of_1s = len([bit for bit in col if bit])
            indexes_of_values_in_col = [value_index for value_index, value in enumerate(col) if value]
            if number_of_1s >= 2 and number_of_1s in dict_inequalities.keys():
                update_constraints_for_more_than_one_bit(constraints, dict_inequalities, i, indexes_of_values_in_col,
                                                         input_vars, number_of_1s, output_vars, x)
            if number_of_1s == 1:
                constraints.append(x[output_vars[i]] == x[input_vars[indexes_of_values_in_col[0]]])

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of variables and constraints for LINEAR LAYER component for the MILP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: present = PresentBlockCipher(number_of_rounds=6)
            sage: milp = MilpModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: linear_layer_component = present.component_from(0, 17)
            sage: variables, constraints = linear_layer_component.milp_xor_linear_mask_propagation_constraints(milp) # long
            sage: variables # long
            [('x[linear_layer_0_17_0_i]', x_0),
            ('x[linear_layer_0_17_1_i]', x_1),
            ...
            ('x[linear_layer_0_17_62_o]', x_126),
            ('x[linear_layer_0_17_63_o]', x_127)]
            sage: constraints # long
            [x_64 == x_0,
            x_65 == x_4,
            ...
            x_126 == x_59,
            x_127 == x_63]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []

        matrix = Matrix(FiniteField(2), self.description)
        inv_matrix = list(matrix.inverse().transpose())

        update_dictionary_that_contains_xor_inequalities_for_specific_matrix(inv_matrix)
        dict_inequalities = output_dictionary_that_contains_xor_inequalities()

        for i in range(len(inv_matrix)):
            col = [row[i] for row in inv_matrix]
            number_of_1s = len([bit for bit in col if bit])
            indexes_of_values_in_col = [value_index for value_index, value in enumerate(col) if value]
            if number_of_1s >= 2:
                update_constraints_for_more_than_one_bit(constraints, dict_inequalities, i, indexes_of_values_in_col,
                                                         input_vars, number_of_1s, output_vars, x)
            if number_of_1s == 1:
                constraints.append(x[output_vars[i]] == x[input_vars[indexes_of_values_in_col[0]]])

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for linear layer
        component in deterministic truncated XOR differential model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: present = PresentBlockCipher(number_of_rounds=6)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: linear_layer_component = present.component_from(0, 17)
            sage: variables, constraints = linear_layer_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[sbox_0_1_0]', x_0),
             ('x_class[sbox_0_1_1]', x_1),
             ...
             ('x_class[linear_layer_0_17_62]', x_126),
             ('x_class[linear_layer_0_17_63]', x_127)]
            sage: constraints
            [x_64 == x_0,
             x_65 == x_4,
             ...
             x_126 == x_59,
             x_127 == x_63]


        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        matrix = self.description
        update_dictionary_that_contains_xor_inequalities_for_specific_matrix(matrix)

        for i in range(len(matrix)):
            col = [row[i] for row in matrix]
            number_of_1s = len([bit for bit in col if bit])
            if number_of_1s >= 2:

                # performing generalized_xor_deterministic_truncated_xor_differential
                a = [x_class[input_vars[j]] for j in range(len(col)) if col[j]]
                list_aj_less_2 = []
                for j in range(len(a)):
                    # a < 2  iff a_less_2 = 1
                    aj_less_2, constr = milp_utils.milp_less(model, a[j], 2, 2)
                    constraints.extend(constr)
                    list_aj_less_2.append(aj_less_2)

                all_aj_less_2, constr = milp_utils.milp_generalized_and(model, list_aj_less_2)
                constraints.extend(constr)

                xor_constr = milp_utils.milp_generalized_xor(a, x_class[output_vars[i]])
                constr = milp_utils.milp_if_then_else(all_aj_less_2, xor_constr, [x_class[output_vars[i]] == 2],
                                                      model._model.get_max(x_class) * len(a))
                constraints.extend(constr)

            if number_of_1s == 1:
                for index, value in enumerate(col):
                    if value:
                        constraints.append(x_class[output_vars[i]] == x_class[input_vars[index]])
                        break

        return variables, constraints


    def milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for linear layer
        component in deterministic truncated XOR differential model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: ascon = AsconSboxSigmaPermutation(number_of_rounds=1)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(ascon)
            sage: milp.init_model_in_sage_milp_class()
            sage: linear_layer_component = ascon.component_from(0, 68)
            sage: variables, constraints = linear_layer_component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)


        """
        x_class = model.trunc_binvar
        x = model.binary_variable

        input_ids, output_ids = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_ids + output_ids]
        matrix = self.description

        input_id_tuples, output_id_tuples = self._get_input_output_variables_tuples()
        linking_constraints = model.link_binary_tuples_to_integer_variables(input_id_tuples + output_id_tuples,
                                                                             input_ids + output_ids)
        constraints = [] + linking_constraints

        for i in range(len(matrix)):
            col = [row[i] for row in matrix]
            number_of_inputs = len([bit for bit in col if bit])
            if number_of_inputs >= 2:
                xor_inputs = [input_id_tuples[j] for j in range(len(col)) if col[j]]
                result_ids = [(f'temp_xor_{j}_{self.id}_{i}_0', f'temp_xor_{j}_{self.id}_{i}_1') for j in
                              range(number_of_inputs - 2)] + [output_id_tuples[i]]
                contains_2, greater_constraints = milp_utils.milp_greater(model, sum(
                    x[input_msb] for input_msb in [id[0] for id in xor_inputs]), 0, len(xor_inputs) + 1)
                constraints.extend(greater_constraints)

                sequential_truncated_xor_constraints = milp_utils.milp_xor_truncated(model, xor_inputs[0], xor_inputs[1], result_ids[0])
                for chunk in range(1, number_of_inputs - 1):
                    sequential_truncated_xor_constraints.extend(milp_utils.milp_xor_truncated(model, xor_inputs[chunk + 1],
                                                                     result_ids[chunk - 1], result_ids[chunk]))
                # if one of the inputs is varied, then the output is varied,
                # else, perform sequential_xor_deterministic_truncated_xor_differential
                constraints.extend(milp_utils.milp_if_then_else(contains_2, [x_class[output_ids[i]] == 2], sequential_truncated_xor_constraints, 6))

            if number_of_inputs == 1:
                for index, value in enumerate(col):
                    if value:
                        constraints.append(x_class[output_ids[i]] == x_class[input_ids[index]])
                        break

        return variables, constraints


    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for linear layer
        component in deterministic truncated XOR differential model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: cipher = MidoriBlockCipher(number_of_rounds=2)
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: linear_layer_component = cipher.component_from(0, 21)
            sage: variables, constraints = linear_layer_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp) # random
            sage: variables
            [('x[mix_column_0_20_word_0_class_bit_0]', x_0),
             ('x[mix_column_0_20_word_0_class_bit_1]', x_1),
            ...
             ('x[mix_column_0_21_14]', x_46),
             ('x[mix_column_0_21_15]', x_47)]
            sage: constraints
            [1 <= 1 + x_6 + x_8 + x_9 + x_10 + x_11 + x_13 + x_18 + x_19 - x_25,
             1 <= 1 + x_6 + x_8 + x_9 + x_10 + x_11 + x_12 + x_13 + x_19 - x_25,
            ...
             1 <= 1 + x_7 - x_8,
             1 <= 1 + x_1 - x_2]

        """
        x = model.binary_variable

        input_vars, output_vars = self._get_wordwise_input_output_full_tuples(model)

        variables = [(f"x[{var}]", x[var]) for sublist in input_vars + output_vars for var in sublist]
        constraints = []

        M = Matrix(self.description)
        if M.ncols() > model.word_size and [len(input) for input in self.input_bit_positions] != [model.word_size] * len(self.input_bit_positions):
            self.print()
            # truncated matrix
            matrix = [[not M[i:i + model.word_size, j:j + model.word_size].is_zero() for j in
                                 range(0, M.ncols(), model.word_size)] for i in range(0, M.nrows(), model.word_size)]
        else:
            matrix = self.description

        if model.word_size <= 4:
            update_dictionary_that_contains_xor_inequalities_for_specific_wordwise_matrix(model.word_size, matrix)
            dict_inequalities = output_dictionary_that_contains_wordwise_truncated_xor_inequalities()

        for i in range(len(matrix)):
            col = [row[i] for row in matrix]
            number_of_1s = len([bit for bit in col if bit])
            if number_of_1s >= 2:
                if model.word_size <= 4:
                    # performing n-inputs wordwise_deterministic_truncated_xor
                    inequalities = dict_inequalities[model.word_size][number_of_1s]
                    active_input_vars = [input_vars[_] for _ in range(len(col)) if col[_]]
                    all_active_vars = [x[_] for sublist in active_input_vars + [output_vars[i]] for _ in sublist]

                    minimized_constraints = espresso_pos_to_constraints(inequalities, all_active_vars)
                    constraints.extend(minimized_constraints)
                else:
                    # performing sequential wordwise_deterministic_truncated_xor
                    xor_inputs = [input_vars[j] for j in range(len(col)) if col[j]]
                    result_ids = [tuple([f'temp_xor_{j}_{self.id}_word_{i}_0', f'temp_xor_{j}_{self.id}_word_{i}_1'] + [f'temp_xor_{j}_{self.id}_word_{i}_bit_{k}' for k in range(model.word_size)]) for j in
                                  range(number_of_1s - 2)] + [output_vars[i]]
                    constraints.extend(
                        milp_utils.milp_xor_truncated_wordwise(model, xor_inputs[0], xor_inputs[1], result_ids[0]))
                    for chunk in range(1, number_of_1s - 1):
                        constraints.extend(milp_utils.milp_xor_truncated_wordwise(model, xor_inputs[chunk + 1],
                                                                         result_ids[chunk - 1], result_ids[chunk]))

            if number_of_1s == 1:
                index = col.index(1)
                for _ in range(len(output_vars[0])):
                    constraints.append(x[output_vars[i][_]] == x[input_vars[index][_]])

        return variables, constraints

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for LINEAR LAYER in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0, 6)
            sage: constraints = linear_layer_component.sat_constraints()
            sage: constraints[1][-1]
            'linear_layer_0_6_23 -sbox_0_0_0 -sbox_0_0_1 -sbox_0_0_2 -sbox_0_0_3 -sbox_0_1_3 -sbox_0_2_1 -sbox_0_3_1 -sbox_0_3_2 -sbox_0_3_3 -sbox_0_4_1 -sbox_0_4_2 -sbox_0_4_3 -sbox_0_5_1 -sbox_0_5_2 -sbox_0_5_3'
        """
        input_bit_len, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        matrix = self.description
        constraints = []
        for i in range(output_bit_len):
            operands = [input_bit_ids[j] for j in range(input_bit_len) if matrix[j][i]]
            constraints.extend(sat_utils.cnf_xor(output_bit_ids[i], operands))

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses for LINEAR LAYER in
        SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0, 6)
            sage: constraints = linear_layer_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            sage: constraints[1][11]
            'inter_0_linear_layer_0_6_0_1 inter_1_linear_layer_0_6_0_0 inter_1_linear_layer_0_6_0_1 -sbox_0_1_0_1'
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        _, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        matrix = self.description
        constraints = []
        for i, out_ids_pair in enumerate(zip(out_ids_0, out_ids_1)):
            operands = [in_ids_pair for j, in_ids_pair in enumerate(zip(in_ids_0, in_ids_1))
                        if matrix[j][i]]
            result_ids = [(f'inter_{j}_{self.id}_{i}_0', f'inter_{j}_{self.id}_{i}_1')
                          for j in range(len(operands) - 2)]
            result_ids.append(out_ids_pair)
            if len(operands) == 1:
                constraints.extend(sat_utils.cnf_equivalent([result_ids[0][0], operands[0][0]]))
                constraints.extend(sat_utils.cnf_equivalent([result_ids[0][1], operands[0][1]]))
            else:
                constraints.extend(sat_utils.cnf_xor_truncated_seq(result_ids, operands))

        return out_ids_0 + out_ids_1, constraints

    def sat_xor_differential_propagation_constraints(self, model):
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for LINEAR LAYER in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0, 6)
            sage: constraints = linear_layer_component.sat_xor_linear_mask_propagation_constraints()
            sage: constraints[1][-1]
            'linear_layer_0_6_23_o -dummy_1_linear_layer_0_6_23_o -dummy_5_linear_layer_0_6_23_o -dummy_7_linear_layer_0_6_23_o -dummy_8_linear_layer_0_6_23_o -dummy_9_linear_layer_0_6_23_o -dummy_14_linear_layer_0_6_23_o -dummy_17_linear_layer_0_6_23_o -dummy_18_linear_layer_0_6_23_o -dummy_23_linear_layer_0_6_23_o'
        """
        input_bit_len, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        inverse_matrix = Matrix(FiniteField(2), self.description).inverse()
        dummy_variables = [[] for _ in range(output_bit_len)]
        constraints = []
        for i in range(input_bit_len):
            operands = [input_bit_ids[i]]
            for j in range(output_bit_len):
                if inverse_matrix[j][i]:
                    variable = f'dummy_{i}_{output_bit_ids[j]}'
                    operands.append(variable)
                    dummy_variables[j].append(variable)
            constraints.extend(sat_utils.cnf_equivalent(operands))
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_xor(output_bit_ids[i], dummy_variables[i]))
        dummy_bit_ids = [d for i in range(output_bit_len) for d in dummy_variables[i]]

        return input_bit_ids + dummy_bit_ids + output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing LINEAR LAYER FOR SMT CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0, 6)
            sage: linear_layer_component.smt_constraints()
            (['linear_layer_0_6_0',
              'linear_layer_0_6_1',
              ...
              'linear_layer_0_6_22',
              'linear_layer_0_6_23'],
             ['(assert (= linear_layer_0_6_0 (xor sbox_0_0_2 sbox_0_0_3 sbox_0_1_0 sbox_0_1_1 sbox_0_1_3 sbox_0_2_0 sbox_0_2_1 sbox_0_3_1 sbox_0_4_2 sbox_0_5_1 sbox_0_5_3)))',
              '(assert (= linear_layer_0_6_1 (xor sbox_0_0_1 sbox_0_0_2 sbox_0_0_3 sbox_0_1_0 sbox_0_1_2 sbox_0_1_3 sbox_0_2_1 sbox_0_2_2 sbox_0_3_1 sbox_0_3_3 sbox_0_4_0 sbox_0_4_1 sbox_0_4_2 sbox_0_4_3 sbox_0_5_0 sbox_0_5_1 sbox_0_5_3)))',
              ...
              '(assert (= linear_layer_0_6_22 (xor sbox_0_0_2 sbox_0_2_2 sbox_0_3_2 sbox_0_4_3 sbox_0_5_0 sbox_0_5_1 sbox_0_5_3)))',
              '(assert (= linear_layer_0_6_23 (xor sbox_0_0_0 sbox_0_0_1 sbox_0_0_2 sbox_0_0_3 sbox_0_1_3 sbox_0_2_1 sbox_0_3_1 sbox_0_3_2 sbox_0_3_3 sbox_0_4_1 sbox_0_4_2 sbox_0_4_3 sbox_0_5_1 sbox_0_5_2 sbox_0_5_3)))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        matrix = self.description
        constraints = []
        for i in range(output_bit_len):
            operands = [input_bit_ids[j] for j in range(len(matrix)) if matrix[j][i]]
            if len(operands) == 1:
                operation = operands[0]
            else:
                operation = smt_utils.smt_xor(operands)
            equation = smt_utils.smt_equivalent((output_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model):
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for LINEAR LAYER in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: linear_layer_component = fancy.component_from(0, 6)
            sage: constraints = linear_layer_component.smt_xor_linear_mask_propagation_constraints()
            sage: constraints[0]
            ['linear_layer_0_6_0_i',
             'linear_layer_0_6_1_i',
             'linear_layer_0_6_2_i',
             'linear_layer_0_6_3_i',
             'linear_layer_0_6_4_i',
             'linear_layer_0_6_5_i',
             'linear_layer_0_6_6_i',
            ...
             'dummy_7_linear_layer_0_6_13_o',
             'dummy_8_linear_layer_0_6_13_o',
             'dummy_9_linear_layer_0_6_13_o',
             'dummy_11_linear_layer_0_6_13_o',
            ...
             'linear_layer_0_6_17_o',
             'linear_layer_0_6_18_o',
             'linear_layer_0_6_19_o',
             'linear_layer_0_6_20_o',
             'linear_layer_0_6_21_o',
             'linear_layer_0_6_22_o',
             'linear_layer_0_6_23_o']
        """
        input_bit_len, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        inverse_matrix = Matrix(FiniteField(2), self.description).inverse()
        dummy_variables = [[] for _ in range(output_bit_len)]
        constraints = []
        for i in range(input_bit_len):
            operands = [input_bit_ids[i]]
            for j in range(output_bit_len):
                if inverse_matrix[j][i]:
                    variable = f'dummy_{i}_{output_bit_ids[j]}'
                    operands.append(variable)
                    dummy_variables[j].append(variable)
            equivalence = smt_utils.smt_equivalent(operands)
            constraints.append(smt_utils.smt_assert(equivalence))
        for i in range(output_bit_len):
            if len(dummy_variables[i]) == 1:
                operation = dummy_variables[i][0]
            else:
                operation = smt_utils.smt_xor(dummy_variables[i])
            equation = smt_utils.smt_equivalent((output_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))
        dummy_bit_ids = [d for i in range(output_bit_len) for d in dummy_variables[i]]

        return input_bit_ids + dummy_bit_ids + output_bit_ids, constraints
