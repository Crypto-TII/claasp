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


from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator


class OR(MultiInputNonlinearLogicalOperator):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size):
        super().__init__(current_round_number, current_round_number_of_components,
                         input_id_links, input_bit_positions, output_bit_size, 'or')

    def algebraic_polynomials(self, model):
        """
        Return polynomials for Boolean OR.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: gift = GiftPermutation(number_of_rounds=1)
            sage: or_component = gift.get_component_from_id("or_0_4")
            sage: algebraic = AlgebraicModel(gift)
            sage: or_component.algebraic_polynomials(algebraic)
            [or_0_4_x0*or_0_4_x32 + or_0_4_y0 + or_0_4_x32 + or_0_4_x0,
             or_0_4_x1*or_0_4_x33 + or_0_4_y1 + or_0_4_x33 + or_0_4_x1,
             or_0_4_x2*or_0_4_x34 + or_0_4_y2 + or_0_4_x34 + or_0_4_x2,
             or_0_4_x3*or_0_4_x35 + or_0_4_y3 + or_0_4_x35 + or_0_4_x3,
             or_0_4_x4*or_0_4_x36 + or_0_4_y4 + or_0_4_x36 + or_0_4_x4,
             or_0_4_x5*or_0_4_x37 + or_0_4_y5 + or_0_4_x37 + or_0_4_x5,
             or_0_4_x6*or_0_4_x38 + or_0_4_y6 + or_0_4_x38 + or_0_4_x6,
             or_0_4_x7*or_0_4_x39 + or_0_4_y7 + or_0_4_x39 + or_0_4_x7,
             or_0_4_x8*or_0_4_x40 + or_0_4_y8 + or_0_4_x40 + or_0_4_x8,
             or_0_4_x9*or_0_4_x41 + or_0_4_y9 + or_0_4_x41 + or_0_4_x9,
             or_0_4_x10*or_0_4_x42 + or_0_4_y10 + or_0_4_x42 + or_0_4_x10,
             or_0_4_x11*or_0_4_x43 + or_0_4_y11 + or_0_4_x43 + or_0_4_x11,
             or_0_4_x12*or_0_4_x44 + or_0_4_y12 + or_0_4_x44 + or_0_4_x12,
             or_0_4_x13*or_0_4_x45 + or_0_4_y13 + or_0_4_x45 + or_0_4_x13,
             or_0_4_x14*or_0_4_x46 + or_0_4_y14 + or_0_4_x46 + or_0_4_x14,
             or_0_4_x15*or_0_4_x47 + or_0_4_y15 + or_0_4_x47 + or_0_4_x15,
             or_0_4_x16*or_0_4_x48 + or_0_4_y16 + or_0_4_x48 + or_0_4_x16,
             or_0_4_x17*or_0_4_x49 + or_0_4_y17 + or_0_4_x49 + or_0_4_x17,
             or_0_4_x18*or_0_4_x50 + or_0_4_y18 + or_0_4_x50 + or_0_4_x18,
             or_0_4_x19*or_0_4_x51 + or_0_4_y19 + or_0_4_x51 + or_0_4_x19,
             or_0_4_x20*or_0_4_x52 + or_0_4_y20 + or_0_4_x52 + or_0_4_x20,
             or_0_4_x21*or_0_4_x53 + or_0_4_y21 + or_0_4_x53 + or_0_4_x21,
             or_0_4_x22*or_0_4_x54 + or_0_4_y22 + or_0_4_x54 + or_0_4_x22,
             or_0_4_x23*or_0_4_x55 + or_0_4_y23 + or_0_4_x55 + or_0_4_x23,
             or_0_4_x24*or_0_4_x56 + or_0_4_y24 + or_0_4_x56 + or_0_4_x24,
             or_0_4_x25*or_0_4_x57 + or_0_4_y25 + or_0_4_x57 + or_0_4_x25,
             or_0_4_x26*or_0_4_x58 + or_0_4_y26 + or_0_4_x58 + or_0_4_x26,
             or_0_4_x27*or_0_4_x59 + or_0_4_y27 + or_0_4_x59 + or_0_4_x27,
             or_0_4_x28*or_0_4_x60 + or_0_4_y28 + or_0_4_x60 + or_0_4_x28,
             or_0_4_x29*or_0_4_x61 + or_0_4_y29 + or_0_4_x61 + or_0_4_x29,
             or_0_4_x30*or_0_4_x62 + or_0_4_y30 + or_0_4_x62 + or_0_4_x30,
             or_0_4_x31*or_0_4_x63 + or_0_4_y31 + or_0_4_x63 + or_0_4_x31]

        """
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        ors_number = self.description[1] - 1
        word_size = noutputs
        ring_R = model.ring()
        input_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        words_vars = [list(map(ring_R, input_vars))[i:i + word_size] for i in range(0, ninputs, word_size)]

        def or_polynomial(x0, x1):
            return x0 * x1 + x0 + x1

        x = [words_vars[0][_] for _ in range(noutputs)]
        for or_itr in range(ors_number):
            for i in range(noutputs):
                x[i] = or_polynomial(x[i], words_vars[or_itr + 1][i])

        y = list(map(ring_R, output_vars))

        polynomials = [y[i] + x[i] for i in range(noutputs)]

        return polynomials

    def cp_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for OR component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.or_component import OR
            sage: or_component = OR(0, 9, ['xor_0_7', 'key'], [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]], 12)
            sage: or_component.cp_constraints()
            (['array[0..11] of var 0..1: or_0_9;',
            'array[0..11] of var 0..1:pre_or_0_9_0;',
            'array[0..11] of var 0..1:pre_or_0_9_1;'],
            ['constraint pre_or_0_9_0[0]=xor_0_7[0];',
             ...
            'constraint pre_or_0_9_1[11]=key[23];',
            'constraint or(pre_or_0_9_0, pre_or_0_9_1, or_0_9);'])
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        numb_of_inp = len(input_id_link)
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        cp_constraints = []
        num_add = self.description[1]
        all_inputs = []
        for i in range(numb_of_inp):
            for j in range(len(input_bit_positions[i])):
                all_inputs.append(f'{input_id_link[i]}[{input_bit_positions[i][j]}]')
        total_input_len = len(all_inputs)
        input_len = total_input_len // num_add
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1: {output_id_link};')
        for i in range(num_add):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..1:pre_{output_id_link}_{i};')
            for j in range(input_len):
                cp_constraints.append(f'constraint pre_{output_id_link}_{i}[{j}]={all_inputs[i * input_len + j]};')
        for i in range(num_add - 2):
            cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1:temp_{output_id_link}_{i};')
        if num_add == 2:
            cp_constraints.append(
                f'constraint or(pre_{output_id_link}_0, pre_{output_id_link}_1, {output_id_link});')
        elif num_add > 2:
            cp_constraints.append(
                f'constraint or(pre_{output_id_link}_0, pre_{output_id_link}_1, temp_{output_id_link}_0);')
            for i in range(1, num_add - 2):
                cp_constraints.append(
                    f'constraint or(pre_{output_id_link}_{i + 1}, temp_{output_id_link}_{i - 1}, '
                    f'temp_{output_id_link}_{i});')
            cp_constraints.append(
                f'constraint or(pre_{output_id_link}_{num_add - 1}, temp_{output_id_link}_{num_add - 3},'
                f'{output_id_link});')

        return cp_declarations, cp_constraints

    def cp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of declarations and constraints for the probability of OR for CP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: gift = GiftPermutation()
            sage: or_component = gift.component_from(39, 6)
            sage: cp = MznModel(gift)
            sage: declarations, constraints = or_component.cp_xor_linear_mask_propagation_constraints(cp)
            sage: declarations
            ['array[0..31] of var 0..3200: p_or_39_6;',
             'array[0..63] of var 0..1:or_39_6_i;',
             'array[0..31] of var 0..1:or_39_6_o;']
           sage: constraints
           ['constraint table([or_39_6_i[0]]++[or_39_6_i[32]]++[or_39_6_o[0]]++[p_or_39_6[0]],and2inputs_LAT);',
            'constraint table([or_39_6_i[1]]++[or_39_6_i[33]]++[or_39_6_o[1]]++[p_or_39_6[1]],and2inputs_LAT);',
            ...
            'constraint table([or_39_6_i[31]]++[or_39_6_i[63]]++[or_39_6_o[31]]++[p_or_39_6[31]],and2inputs_LAT);',
            'constraint p[0] = sum(p_or_39_6);']

        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        cp_declarations = []
        cp_constraints = []
        num_add = self.description[1]
        input_len = input_size // num_add
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..{100 * output_size}: p_{output_id_link};')
        cp_declarations.append(f'array[0..{input_size - 1}] of var 0..1:{output_id_link}_i;')
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1:{output_id_link}_o;')
        model.component_and_probability[output_id_link] = 0
        p_count = 0
        for i in range(output_size):
            new_constraint = f'constraint table('
            for j in range(num_add):
                new_constraint = new_constraint + f'[{output_id_link}_i[{i + input_len * j}]]++'
            new_constraint = new_constraint + f'[{output_id_link}_o[{i}]]++[p_{output_id_link}[{p_count}]],and{num_add}inputs_LAT);'
            cp_constraints.append(new_constraint)
            p_count = p_count + 1
        cp_constraints.append(f'constraint p[{model.c}] = sum(p_{output_id_link});')
        model.component_and_probability[output_id_link] = model.c
        model.c = model.c + 1
        result = cp_declarations, cp_constraints

        return result

    def generic_sign_linear_constraints(self, inputs, outputs):
        """
        Return the constraints for finding the sign of an OR component.

        INPUT:

        - ``inputs`` -- **list**; a list representing the inputs to the OR
        - ``outputs`` -- **list**; a list representing the output to the OR

        EXAMPLES::

            sage: from claasp.components.or_component import OR
            sage: or_component = OR(31, 14, ['xor_0_7', 'key'], [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]], 12)
            sage: input = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            sage: output = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            sage: or_component.generic_sign_linear_constraints(input, output)
            1
        """
        sign = +1
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        or_LAT = [[[1, -1], [0, 1]], [[0, 1], [0, 1]]]
        for i in range(output_size):
            sign = sign * or_LAT[inputs[i]][inputs[input_size // 2 + i]][outputs[i]]

        return sign

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = bit_vector_OR([{",".join(params)} ], {self.description[1]}, {self.output_bit_size})']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_OR({params})']

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for OR operation in SAT CIPHER model.

        This method support AND operation using more than two operands.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: or_component = gift.component_from(0, 4)
            sage: or_component.sat_constraints()
            (['or_0_4_0',
              'or_0_4_1',
              'or_0_4_2',
              ...
              'or_0_4_31 -xor_0_3_31',
              'or_0_4_31 -xor_0_1_31',
              '-or_0_4_31 xor_0_3_31 xor_0_1_31'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_or(output_bit_ids[i], input_bit_ids[i::output_bit_len]))

        return output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts for OR operation in SMT CIPHER model.

        This method support OR operation using more than two operands.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: or_component = gift.component_from(0, 4)
            sage: or_component.smt_constraints()
            (['or_0_4_0',
              'or_0_4_1',
              ...
              'or_0_4_30',
              'or_0_4_31'],
             ['(assert (= or_0_4_0 (or xor_0_3_0 xor_0_1_0)))',
              '(assert (= or_0_4_1 (or xor_0_3_1 xor_0_1_1)))',
              ...
              '(assert (= or_0_4_30 (or xor_0_3_30 xor_0_1_30)))',
              '(assert (= or_0_4_31 (or xor_0_3_31 xor_0_1_31)))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            operation = smt_utils.smt_or(input_bit_ids[i::output_bit_len])
            equation = smt_utils.smt_equivalent((output_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints
