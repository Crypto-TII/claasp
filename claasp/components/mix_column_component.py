
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


from copy import deepcopy

from sage.all import ZZ
from sage.matrix.constructor import Matrix
from sage.structure.sequence import Sequence
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import FiniteField
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing

from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_mds_matrices import \
    update_dictionary_that_contains_wordwise_truncated_mds_inequalities, \
    output_dictionary_that_contains_wordwise_truncated_mds_inequalities, \
    delete_dictionary_that_contains_wordwise_truncated_mds_inequalities
from claasp.cipher_modules.models.milp.utils.utils import espresso_pos_to_constraints
from claasp.input import Input
from claasp.component import Component, free_input
from claasp.utils.utils import int_to_poly
from claasp.components.linear_layer_component import LinearLayer
from claasp.cipher_modules.component_analysis_tests import binary_matrix_of_linear_component, branch_number, has_maximal_branch_number


def add_xor_components(word_size, output_id_link_1, output_id_link_2, output_size, list_of_xor_components):
    for i in range(output_size // word_size):
        input_id_link = [output_id_link_1, output_id_link_2,
                         f'output_xor_{output_id_link_1}_{output_id_link_2}']
        input_bit_positions = [[] for _ in range(3)]
        for index in range(word_size):
            for m in range(3):
                input_bit_positions[m].append(i * word_size + index)
        input_bit_positions = [x for x in input_bit_positions if x != []]
        input_len = 0
        for input_bit in input_bit_positions:
            input_len += len(input_bit)
        component_input = Input(input_len, input_id_link, input_bit_positions)
        xor_component = Component("", "word_operation", component_input, input_len, ['XOR', 3])
        list_of_xor_components.append(xor_component)


def calculate_input_bit_positions(word_size, word_index, input_name_1, input_name_2,
                                  new_input_bit_positions_1, new_input_bit_positions_2):
    input_bit_positions = [[] for _ in range(3)]
    if input_name_1 != input_name_2:
        input_bit_positions[0] = [int(new_input_bit_positions_1) * word_size + index
                                  for index in range(word_size)]
        input_bit_positions[1] = [word_index * word_size + index for index in range(word_size)]
        input_bit_positions[2] = [int(new_input_bit_positions_2) * word_size + index
                                  for index in range(word_size)]
    else:
        input_bit_positions[0] = [int(new_input_bit_positions_1) * word_size + index
                                  for index in range(word_size)]
        input_bit_positions[0] += [int(new_input_bit_positions_2) * word_size + index
                                   for index in range(word_size)]
        input_bit_positions[1] = [word_index * word_size + index for index in range(word_size)]

    return input_bit_positions


def cp_get_all_inputs(word_size, input_bit_positions, input_id_link, numb_of_inp):
    all_inputs = []
    for i in range(numb_of_inp):
        for j in range(len(input_bit_positions[i]) // word_size):
            all_inputs.append(f'{input_id_link[i]}'
                              f'[{input_bit_positions[i][j * word_size] // word_size}]')

    return all_inputs


class MixColumn(LinearLayer):
    def __init__(self, current_round_number, current_round_number_of_components, input_id_links,
                 input_bit_positions, output_bit_size, description):
        super().__init__(current_round_number, current_round_number_of_components, input_id_links,
                         input_bit_positions, output_bit_size, description)
        self._id = f'mix_column_{current_round_number}_{current_round_number_of_components}'
        self._type = 'mix_column'

    def _cp_add_declarations_and_constraints(self, word_size, mix_column_mant, list_of_xor_components,
                                             cp_constraints, cp_declarations, mix_column_name):
        for component_mix in mix_column_mant:
            variables, constraints = self._cp_create_component(word_size, component_mix, mix_column_name,
                                                               list_of_xor_components)
            cp_declarations.extend(variables)
            cp_constraints.extend(constraints)

    def _cp_build_truncated_table(self, word_size):
        """
        Return a model that generates the list of possible input/output couples for the given MIX COLUMN for CP.

        INPUT:

        - ``word_size`` -- **integer**; the size of the word

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: mix_column_component = aes.component_from(0, 21)
            sage: mix_column_component._cp_build_truncated_table(cp.word_size)
            'array[0..93, 1..8] of int: mix_column_truncated_table_mix_column_0_21 = array2d(0..93, 1..8, [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,0,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,1,0,1,0,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,0,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1]);'
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        branch = branch_number(self, 'differential', 'word')
        total_size = (input_size + output_size) // word_size
        table_items = ''
        solutions = 0
        for i in range(2 ** total_size):
            binary_i = f'{i:0{total_size}b}'
            bit_sum = sum(int(x) for x in binary_i)
            if bit_sum == 0 or bit_sum >= branch:
                table_items += binary_i
                solutions += 1
        table = ','.join(table_items)
        mix_column_table = f'array[0..{solutions - 1}, 1..{total_size}] of int: ' \
                           f'mix_column_truncated_table_{output_id_link} = ' \
                           f'array2d(0..{solutions - 1}, 1..{total_size}, [{table}]);'

        return mix_column_table

    def _cp_create_component(self, word_size, component, mix_column_name, list_of_xor_components):
        """
        Create a new MIX COLUMN component which input/output is the sum of the inputs/outputs of two MIX COLUMNS for CP.

        INPUT:

        - ``word_size`` -- **integer**; the size of the word
        - ``component`` -- **Component object**; the second mix column component from the Cipher
        - ``mix_column_name`` -- **string**; the name of the mix_column component to which the truncated table will refer
        - ``list_of_xor_components`` -- **list of objects**; the list of the xor components of the cipher

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: mix_column_component_1 = aes.component_from(0, 21)
            sage: mix_column_component_2 = aes.component_from(0, 22)
            sage: mix_column_component_1._cp_create_component(cp.word_size, mix_column_component_2, 1, cp.list_of_xor_components)
            (['array[0..3] of var 0..1: input_xor_mix_column_0_22_mix_column_0_21;',
              'array[0..3] of var 0..1: output_xor_mix_column_0_22_mix_column_0_21;'],
             ['constraint table([input_xor_mix_column_0_22_mix_column_0_21[s]|s in 0..3]++[output_xor_mix_column_0_22_mix_column_0_21[s]|s in 0..3],mix_column_truncated_table_1);'])
        """
        cp_declarations = []
        cp_constraints = []
        if component.description[0] != self.description[0]:
            return cp_declarations, cp_constraints

        input_id_link_1 = component.input_id_links
        all_inputs_1 = cp_get_all_inputs(word_size, component.input_bit_positions, input_id_link_1,
                                         len(input_id_link_1))
        input_id_link_2 = self.input_id_links
        all_inputs_2 = cp_get_all_inputs(word_size, self.input_bit_positions, input_id_link_2,
                                         len(input_id_link_2))
        input_size = int(component.input_bit_size)
        output_id_link_1 = component.id
        output_id_link_2 = self.id
        cp_declarations.append(
            f'array[0..{(input_size - 1) // word_size}] of var 0..1: input_xor_{output_id_link_1}_{output_id_link_2};')
        cp_declarations.append(
            f'array[0..{(input_size - 1) // word_size}] of var 0..1: output_xor_{output_id_link_1}_{output_id_link_2};')
        for word_index in range(input_size // word_size):
            input_id_link = []
            divide_1 = all_inputs_1[word_index].partition('[')
            input_name_1 = divide_1[0]
            new_input_bit_positions_1 = divide_1[2][:-1]
            divide_2 = all_inputs_2[word_index].partition('[')
            input_name_2 = divide_2[0]
            new_input_bit_positions_2 = divide_2[2][:-1]
            if all_inputs_1[word_index] == all_inputs_2[word_index]:
                input_bit_positions = [[] for _ in range(3)]
                cp_constraints.append(
                    f'constraint input_xor_{output_id_link_1}_{output_id_link_2}[{word_index}] = 0')
            else:
                input_id_link.append(input_name_1)
                input_id_link.append(f'input_xor_{output_id_link_1}_{output_id_link_2}')
                if input_name_1 != input_name_2:
                    input_id_link.append(input_name_2)
                input_bit_positions = calculate_input_bit_positions(word_size, word_index,
                                                                    input_name_1, input_name_2,
                                                                    new_input_bit_positions_1,
                                                                    new_input_bit_positions_2)
            input_bit_positions = [x for x in input_bit_positions if x != []]
            input_len = 0
            for input_bit in input_bit_positions:
                input_len += len(input_bit)
            component_input = Input(input_len, input_id_link, input_bit_positions)
            xor_component = Component("", "word_operation", component_input, input_len, ['XOR', 3])
            list_of_xor_components.append(xor_component)
        new_constraint = 'constraint table('
        new_constraint += f'[input_xor_{output_id_link_1}_{output_id_link_2}[s]|s in ' \
                          f'0..{(input_size - 1) // word_size}]++'
        new_constraint += f'[output_xor_{output_id_link_1}_{output_id_link_2}[s]|s in ' \
                          f'0..{(input_size - 1) // word_size}]'
        new_constraint += f',mix_column_truncated_table_{mix_column_name});'
        cp_constraints.append(new_constraint)
        output_size = int(component.output_bit_size)
        add_xor_components(word_size, output_id_link_1, output_id_link_2, output_size, list_of_xor_components)

        return cp_declarations, cp_constraints

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for MIX COLUMN operation.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: midori = MidoriBlockCipher(number_of_rounds=16)
            sage: mix_column = midori.get_component_from_id("mix_column_0_20")
            sage: mix_column.algebraic_polynomials(AlgebraicModel(midori))
            [mix_column_0_20_x0 + mix_column_0_20_y0,
             mix_column_0_20_x1 + mix_column_0_20_y1,
             mix_column_0_20_x2 + mix_column_0_20_y2,
             ...
             mix_column_0_20_y61^2 + mix_column_0_20_y61,
             mix_column_0_20_y62^2 + mix_column_0_20_y62,
             mix_column_0_20_y63^2 + mix_column_0_20_y63]
        """
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size

        deg_of_extension = self.description[2]
        if self.description[1] != 0:
            coefficient_vector = ZZ(self.description[1]).digits(base=2)
            E = FiniteField(2 ** deg_of_extension, name='Z', modulus=coefficient_vector)
        else:
            E = FiniteField(2 ** deg_of_extension)

        init_matrix = self.description[0]
        M = Matrix(E, [[E.fetch_int(value) for value in row] for row in init_matrix])

        ninput_words = M.ncols()
        noutput_words = M.nrows()

        var_names_X = [f"X{i}" for i in range(ninput_words)]
        var_names_Y = [f"Y{i}" for i in range(noutput_words)]
        P = PolynomialRing(E, ninput_words + noutput_words, var_names_X + var_names_Y)
        X = vector(P, [P(Xi) for Xi in var_names_X])
        Y = vector(P, [P(Yi) for Yi in var_names_Y])

        F = Sequence((M * X).list()[i] + Y[i] for i in range(noutput_words)).weil_restriction()

        input_vars = [self.id + '_' + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + '_' + model.output_postfix + str(i) for i in range(noutputs)]
        ring_R = F.ring().change_ring(names=input_vars + output_vars)

        polynomials = [ring_R(f) for f in F]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for MIX COLUMN in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=3)
            sage: mix_column_component = midori.component_from(0, 23)
            sage: mix_column_component.cms_constraints()
            (['mix_column_0_23_0',
              'mix_column_0_23_1',
              'mix_column_0_23_2',
              ...
              '-mix_column_0_23_15 -mix_column_0_20_35 mix_column_0_20_39 -mix_column_0_20_43',
              '-mix_column_0_23_15 mix_column_0_20_35 -mix_column_0_20_39 -mix_column_0_20_43',
              'mix_column_0_23_15 -mix_column_0_20_35 -mix_column_0_20_39 -mix_column_0_20_43'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model):
        return self.cms_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_xor_linear_mask_propagation_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for MIX COLUMN component for the CP cipher model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: mix_column_component = aes.component_from(0, 21)
            sage: mix_column_component.cp_constraints()
            ([],
             ['constraint mix_column_0_21[0] = (rot_0_17[1] + rot_0_18[0] + rot_0_18[1] + rot_0_19[0] + rot_0_20[0]) mod 2;',
              ...
              'constraint mix_column_0_21[31] = (rot_0_17[0] + rot_0_17[7] + rot_0_18[7] + rot_0_19[7] + rot_0_20[0]) mod 2;'])
        """
        matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[matrix[i][j] for i in range(matrix.nrows())]
                             for j in range(matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        cp_declarations, cp_constraints = super().cp_constraints()
        self.set_description(original_description)

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_constraints(self, inverse=False):
        r"""
        Return lists declarations and constraints for MIX COLUMN component for the CP deterministic truncated xor differential model.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: mix_column_component = aes.component_from(0, 21)
            sage: mix_column_component.cp_deterministic_truncated_xor_differential_constraints()
            ([],
             ['constraint if ((rot_0_17[1] < 2) /\\ (rot_0_18[0] < 2) /\\ (rot_0_18[1] < 2) /\\ (rot_0_19[0] < 2) /\\ (rot_0_20[0]< 2)) then mix_column_0_21[0] = (rot_0_17[1] + rot_0_18[0] + rot_0_18[1] + rot_0_19[0] + rot_0_20[0]) mod 2 else mix_column_0_21[0] = 2 endif;',
               ...
              'constraint if ((rot_0_17[0] < 2) /\\ (rot_0_17[7] < 2) /\\ (rot_0_18[7] < 2) /\\ (rot_0_19[7] < 2) /\\ (rot_0_20[0]< 2)) then mix_column_0_21[31] = (rot_0_17[0] + rot_0_17[7] + rot_0_18[7] + rot_0_19[7] + rot_0_20[0]) mod 2 else mix_column_0_21[31] = 2 endif;'])
        """
        matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[matrix[i][j] for i in range(matrix.nrows())]
                             for j in range(matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        cp_declarations, cp_constraints = super().cp_deterministic_truncated_xor_differential_constraints()
        self.set_description(original_description)

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        """
        Return declarations and constraints for MIX COLUMN component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: mix_column_component = aes.component_from(0, 21)
            sage: mix_column_component.cp_xor_differential_propagation_first_step_constraints(cp)
            (['array[0..3] of var 0..1: mix_column_0_21;',
              'array[0..93, 1..8] of int: mix_column_truncated_table_mix_column_0_21 = array2d(0..93, 1..8, [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,0,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,1,0,1,0,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,0,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1]);'],
             ['constraint table([rot_0_17[0]]++[rot_0_18[0]]++[rot_0_19[0]]++[rot_0_20[0]]++[mix_column_0_21[0]]++[mix_column_0_21[1]]++[mix_column_0_21[2]]++[mix_column_0_21[3]], mix_column_truncated_table_mix_column_0_21);'])
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        description = self.description
        numb_of_inp = len(input_id_link)
        all_inputs = []
        mix_column_name = output_id_link
        number_of_mix = 0
        is_mix = False
        additional_constraint = 'no'
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
        cp_declarations = []
        if is_mix:
            cp_declarations.append(f'array[0..{number_of_mix - 1}] of var 0..1: {output_id_link}_i;')
        cp_declarations.append(f'array[0..{(output_size - 1) // model.word_size}] of var 0..1: {output_id_link};')
        already_in = False
        for mant in model.mix_column_mant:
            if description == mant.description:
                already_in = True
                mix_column_name = mant.id
                break
        if not already_in:
            cp_declarations.append(self._cp_build_truncated_table(model.word_size))
        table_inputs = '++'.join([f'[{input_}]' for input_ in all_inputs])
        table_outputs = '++'.join([f'[{output_id_link}[{i}]]' for i in range(output_size // model.word_size)])
        new_constraint = f'constraint table({table_inputs}++{table_outputs}, ' \
                         f'mix_column_truncated_table_{mix_column_name});'
        cp_constraints = [new_constraint]
        if additional_constraint == 'yes':
            self._cp_add_declarations_and_constraints(model.word_size, model.mix_column_mant,
                                                      model.list_of_xor_components, cp_constraints,
                                                      cp_declarations, mix_column_name)
        model.mix_column_mant.append(self)
        result = cp_declarations, cp_constraints

        return result

    def cp_xor_differential_propagation_constraints(self, model):
        return self.cp_constraints()

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for MIX COLUMN component for the CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: mix_column_component = aes.component_from(0, 21)
            sage: mix_column_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..31] of var 0..1:mix_column_0_21_i;',
              'array[0..31] of var 0..1:mix_column_0_21_o;'],
             ['constraint mix_column_0_21_i[0]=(mix_column_0_21_o[1]+mix_column_0_21_o[2]+mix_column_0_21_o[3]+mix_column_0_21_o[8]+mix_column_0_21_o[9]+mix_column_0_21_o[11]+mix_column_0_21_o[16]+mix_column_0_21_o[18]+mix_column_0_21_o[19]+mix_column_0_21_o[24]+mix_column_0_21_o[27]) mod 2;',
              ...
              'constraint mix_column_0_21_i[31]=(mix_column_0_21_o[0]+mix_column_0_21_o[2]+mix_column_0_21_o[7]+mix_column_0_21_o[9]+mix_column_0_21_o[10]+mix_column_0_21_o[15]+mix_column_0_21_o[18]+mix_column_0_21_o[23]+mix_column_0_21_o[24]+mix_column_0_21_o[25]+mix_column_0_21_o[26]) mod 2;'])
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        matrix_component = binary_matrix_of_linear_component(self)
        cp_declarations = []
        cp_constraints = []
        matrix = Matrix(FiniteField(2), matrix_component)
        inverse_matrix = matrix.inverse()
        cp_declarations.append(f'array[0..{input_size - 1}] of var 0..1:{output_id_link}_i;')
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1:{output_id_link}_o;')
        for i in range(input_size):
            new_constraint = f'constraint {output_id_link}_i[{i}]=('
            for j in range(input_size):
                if inverse_matrix[i][j] == 1:
                    new_constraint = new_constraint + f'{output_id_link}_o[{j}]+'
            new_constraint = new_constraint[:-1] + ') mod 2;'
            cp_constraints.append(new_constraint)
        result = cp_declarations, cp_constraints
        return result

    def get_bit_based_cuda_code(self, verbosity):
        mix_column_code = []
        self.select_bits_cuda(mix_column_code)
        len_description_list = len(self.description[0])

        mix_column_code.append(f'\tmatrix = new uint64_t*[{len_description_list}];\n')

        for k, row in enumerate(self.description[0]):
            len_row = len(row)
            mix_column_code.append(
                f'\tmatrix[{k}] = new uint64_t[{len_row}] {{{", ".join([str(x) for x in row])}}};')


        mix_column_code.append(
            f'\tBitString* {self.id} = '
            f'MIX_COLUMNS(input, matrix, {self.description[1]}, {self.description[2]});\n')

        for k, position_list in enumerate(self.description[0]):
            mix_column_code.append(f'\tdelete [] matrix[{k}];')
        mix_column_code.append(f'\tdelete [] matrix;')

        if verbosity:
            self.print_values(mix_column_code)

        free_input(mix_column_code)

        return mix_column_code

    def get_bit_based_c_code(self, verbosity):
        mix_column_code = []
        self.select_bits(mix_column_code)

        mix_column_code.append('\tmatrix = (uint64_t*[]) {')
        for row in self.description[0]:
            mix_column_code.append(f'\t\t(uint64_t[]) {{{", ".join([str(x) for x in row])}}},')
        mix_column_code.append('\t};')

        mix_column_code.append(
            f'\tBitString* {self.id} = '
            f'MIX_COLUMNS(input, matrix, {self.description[1]}, {self.description[2]});\n')

        if verbosity:
            self.print_values(mix_column_code)

        free_input(mix_column_code)

        return mix_column_code

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        matrix = self.description[0]
        polynomial = self.description[1]
        input_size = self.description[2]
        params_mix_column = ''
        mul_tables = ''
        if polynomial > 0 and polynomial != 257:
            mul_tables = dict()
            F2 = FiniteField(2)['x']
            _modulus = int_to_poly(polynomial, input_size + 1, F2.gen())
            F = FiniteField(pow(2, input_size), name='a', modulus=_modulus)
            for row in matrix:
                for element in row:
                    if element not in mul_tables:
                        mul_tables[element] = [(F.fetch_int(i) * F.fetch_int(element)).integer_representation()
                                               for i in range(2 ** input_size)]
            params_mix_column = [
                f'bit_vector_select_word({self.input_id_links[i]},  {self.input_bit_positions[i]})'
                for i in range(len(self.input_id_links))]

        return [f'  {self.id} = bit_vector_mix_column(bit_vector_CONCAT([{",".join(params_mix_column)} ]), '
                f'{matrix}, {mul_tables}, {input_size})']

    def get_byte_based_vectorized_python_code(self, params):
        matrix = self.description[0]
        polynomial = self.description[1]
        input_size = self.description[2]
        if polynomial > 0 and polynomial != 257:  # check if in 0..2**n-1
            mul_tables = dict()
            F2 = FiniteField(2)['x']
            _modulus = int_to_poly(polynomial, input_size + 1, F2.gen())
            F = FiniteField(pow(2, input_size), name='a', modulus=_modulus)

            for row in matrix:
                for element in row:
                    if element not in mul_tables:
                        mul_tables[element] = [(F.fetch_int(i) * F.fetch_int(element)).integer_representation()
                                               for i in range(2 ** input_size)]
            return [f'  {self.id}=byte_vector_mix_column({params} , {matrix}, {mul_tables}, {input_size})']
        return [f'  {self.id}=byte_vector_mix_column_poly0({params} , {matrix}, {input_size})']

    def milp_constraints(self, model):
        """
        Return lists of variables and constrains modeling a component of type MIX COLUMN for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: milp = MilpModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: mix_column_component = aes.component_from(0, 21)
            sage: variables, constraints = mix_column_component.milp_constraints(milp)
            ...
            sage: variables
            [('x[rot_0_17_0]', x_0),
            ('x[rot_0_17_1]', x_1),
            ...
            ('x[mix_column_0_21_30]', x_62),
            ('x[mix_column_0_21_31]', x_63)]
            sage: constraints[:3]
            [1 <= 1 - x_1 + x_8 + x_9 + x_16 + x_24 + x_32,
             1 <= 1 + x_1 - x_8 + x_9 + x_16 + x_24 + x_32,
             1 <= 1 + x_1 + x_8 - x_9 + x_16 + x_24 + x_32]
        """
        bin_matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[bin_matrix[i][j] for i in range(bin_matrix.nrows())]
                             for j in range(bin_matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        variables, constraints = super().milp_constraints(model)
        self.set_description(original_description)

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of variables and constraints for MIX COLUMN component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: skinny = SkinnyBlockCipher(block_bit_size=128, number_of_rounds=2)
            sage: milp = MilpModel(skinny)
            sage: milp.init_model_in_sage_milp_class()
            sage: mix_column_component = skinny.component_from(0, 31)
            sage: variables, constraints = mix_column_component.milp_xor_linear_mask_propagation_constraints(milp)
            ...
            sage: variables
            [('x[mix_column_0_31_0_i]', x_0),
             ('x[mix_column_0_31_1_i]', x_1),
            ...
             ('x[mix_column_0_31_30_o]', x_62),
             ('x[mix_column_0_31_31_o]', x_63)]
            sage: constraints
            [x_32 == x_24,
             x_33 == x_25,
            ...
            1 <= 3 - x_15 + x_23 - x_31 - x_63,
            1 <= 3 + x_15 - x_23 - x_31 - x_63]
        """
        bin_matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[bin_matrix[i][j] for i in range(bin_matrix.nrows())]
                             for j in range(bin_matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        variables, constraints = super().milp_xor_linear_mask_propagation_constraints(model)
        self.set_description(original_description)
        result = variables, constraints
        return result

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for mix column
        component in deterministic truncated XOR differential model.

        For MDS matrices, this method implements Model 5 from https://tosc.iacr.org/index.php/ToSC/article/view/8702/8294
        INPUTS:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: mix_column_component = aes.component_from(0, 21)
            sage: variables, constraints = mix_column_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp) # random
            sage: variables
            [('x[rot_0_17_word_0_class_bit_0]', x_0),
             ('x[rot_0_17_word_0_class_bit_1]', x_1),
             ...
             ('x[mix_column_0_21_word_3_class_bit_0]', x_14),
             ('x[mix_column_0_21_word_3_class_bit_1]', x_15)]
            sage: constraints
            [1 <= 1 + x_0 + x_1 + x_2 + x_3 + x_4 + x_5 + x_6 - x_15,
             1 <= 1 + x_0 + x_1 + x_2 + x_3 + x_4 + x_5 + x_7 - x_15,
             ...
            1 <= 1 - x_11 + x_13,
            1 <= 1 - x_9 + x_11]

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: cipher = MidoriBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: mix_column_component = cipher.component_from(0, 21)
            sage: variables, constraints = mix_column_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            ...

        """

        constraints = []

        if has_maximal_branch_number(self):
            x = model.binary_variable
            input_class_tuple, output_class_tuple = self._get_wordwise_input_output_linked_class_tuples(model)
            variables = [(f"x[{var_elt}]", x[var_elt]) for var_tuple in input_class_tuple + output_class_tuple for
                         var_elt in var_tuple]

            matrix = Matrix(self.description[0])
            all_vars = [x[i] for _ in input_class_tuple + output_class_tuple for i in _]

            update_dictionary_that_contains_wordwise_truncated_mds_inequalities(model._word_size, matrix.dimensions())
            dict_inequalities = output_dictionary_that_contains_wordwise_truncated_mds_inequalities()
            inequalities = dict_inequalities[model._word_size][matrix.dimensions()]

            minimized_constraints = espresso_pos_to_constraints(inequalities, all_vars)
            constraints.extend(minimized_constraints)
        else:
            M = self.description[0]
            bin_matrix = Matrix([[1 if M[i][j] else 0 for i in range(len(M))]
                                 for j in range(len(M[0]))])
            bin_matrix_transposed = [list(_) for _ in list(zip(*bin_matrix))]
            self.set_description(bin_matrix_transposed)
            variables, constraints = super().milp_wordwise_deterministic_truncated_xor_differential_constraints(model)
        return variables, constraints

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for MIX COLUMN in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=3)
            sage: mix_column_component = midori.component_from(0, 23)
            sage: mix_column_component.sat_constraints()
            (['mix_column_0_23_0',
              'mix_column_0_23_1',
              'mix_column_0_23_2',
              ...
              '-mix_column_0_23_15 -mix_column_0_20_35 mix_column_0_20_39 -mix_column_0_20_43',
              '-mix_column_0_23_15 mix_column_0_20_35 -mix_column_0_20_39 -mix_column_0_20_43',
              'mix_column_0_23_15 -mix_column_0_20_35 -mix_column_0_20_39 -mix_column_0_20_43'])
        """
        matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[matrix[i][j] for i in range(matrix.nrows())]
                             for j in range(matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        variables, constraints = super().sat_constraints()
        self.set_description(original_description)
        result = variables, constraints
        return result

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses for MIX COLUMN in SAT
        DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=3)
            sage: mix_column_component = midori.component_from(0, 23)
            sage: out_ids, constraints = mix_column_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            sage: constraints[7]
            'mix_column_0_23_0_0 -inter_0_mix_column_0_23_0_0'
        """
        matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[matrix[i][j] for i in range(matrix.nrows())]
                             for j in range(matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        out_ids, constraints = super().sat_bitwise_deterministic_truncated_xor_differential_constraints()
        self.set_description(original_description)
        return out_ids, constraints

    def sat_xor_differential_propagation_constraints(self, model):
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for MIX COLUMN in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=3)
            sage: mix_column_component = midori.component_from(0, 23)
            sage: mix_column_component.sat_xor_linear_mask_propagation_constraints()
            (['mix_column_0_23_0_i',
              'mix_column_0_23_1_i',
              'mix_column_0_23_2_i',
              ...
              '-mix_column_0_23_15_o -dummy_3_mix_column_0_23_15_o dummy_7_mix_column_0_23_15_o -dummy_11_mix_column_0_23_15_o',
              '-mix_column_0_23_15_o dummy_3_mix_column_0_23_15_o -dummy_7_mix_column_0_23_15_o -dummy_11_mix_column_0_23_15_o',
              'mix_column_0_23_15_o -dummy_3_mix_column_0_23_15_o -dummy_7_mix_column_0_23_15_o -dummy_11_mix_column_0_23_15_o'])
        """
        matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[matrix[i][j] for i in range(matrix.nrows())]
                             for j in range(matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        variables, constraints = super().sat_xor_linear_mask_propagation_constraints()
        self.set_description(original_description)
        result = variables, constraints
        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing MIX COLUMN for SMT CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=3)
            sage: mix_column_component = midori.component_from(0, 23)
            sage: mix_column_component.smt_constraints()
            (['mix_column_0_23_0',
              'mix_column_0_23_1',
              ...
              'mix_column_0_23_14',
              'mix_column_0_23_15'],
             ['(assert (= mix_column_0_23_0 (xor mix_column_0_20_36 mix_column_0_20_40 mix_column_0_20_44)))',
              '(assert (= mix_column_0_23_1 (xor mix_column_0_20_37 mix_column_0_20_41 mix_column_0_20_45)))',
              ...
              '(assert (= mix_column_0_23_14 (xor mix_column_0_20_34 mix_column_0_20_38 mix_column_0_20_42)))',
              '(assert (= mix_column_0_23_15 (xor mix_column_0_20_35 mix_column_0_20_39 mix_column_0_20_43)))'])
        """
        matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[matrix[i][j] for i in range(matrix.nrows())]
                             for j in range(matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        variables, constraints = super().smt_constraints()
        self.set_description(original_description)
        result = variables, constraints
        return result

    def smt_xor_differential_propagation_constraints(self, model):
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for MIX COLUMN in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=3)
            sage: mix_column_component = midori.component_from(0, 23)
            sage: mix_column_component.smt_xor_linear_mask_propagation_constraints()
            (['mix_column_0_23_0_i',
              'mix_column_0_23_1_i',
              ...
              'mix_column_0_23_14_o',
              'mix_column_0_23_15_o'],
             ['(assert (= mix_column_0_23_0_i dummy_0_mix_column_0_23_4_o dummy_0_mix_column_0_23_8_o dummy_0_mix_column_0_23_12_o))',
              '(assert (= mix_column_0_23_1_i dummy_1_mix_column_0_23_5_o dummy_1_mix_column_0_23_9_o dummy_1_mix_column_0_23_13_o))',
              ...
              '(assert (= mix_column_0_23_14_o (xor dummy_2_mix_column_0_23_14_o dummy_6_mix_column_0_23_14_o dummy_10_mix_column_0_23_14_o)))',
              '(assert (= mix_column_0_23_15_o (xor dummy_3_mix_column_0_23_15_o dummy_7_mix_column_0_23_15_o dummy_11_mix_column_0_23_15_o)))'])
        """
        matrix = binary_matrix_of_linear_component(self)
        matrix_transposed = [[matrix[i][j] for i in range(matrix.nrows())]
                             for j in range(matrix.ncols())]
        original_description = deepcopy(self.description)
        self.set_description(matrix_transposed)
        variables, constraints = super().smt_xor_linear_mask_propagation_constraints()
        self.set_description(original_description)
        result = variables, constraints
        return result
