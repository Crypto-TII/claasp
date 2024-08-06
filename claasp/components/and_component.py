
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
from claasp.cipher_modules.models.milp.utils import utils as milp_utils
from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator


def cp_twoterms(model, inp1, inp2, out, cp_constraints):
    cp_constraints.append(f'constraint Ham_weight(Andz({inp1}, {inp2}, {out})) == 0 /\\ p[{model.c}] = '
                          f'Ham_weight(OR({inp1}, {inp2}));')
    return cp_constraints


def cp_xor_differential_probability_ddt(numadd):
    """
    Return the ddt of the AND operation for CP xor differential probability.

    INPUT:

    - ``numadd`` -- **integer**; the number of addenda

    EXAMPLES::

        sage: from claasp.components.and_component import cp_xor_differential_probability_ddt
        sage: cp_xor_differential_probability_ddt(2)
        [4, 0, 2, 2, 2, 2, 2, 2]
    """
    n = pow(2, numadd)
    ddt_table = []
    for i in range(n):
        for m in range(2):
            count = 0
            for j in range(n):
                k = i ^ j
                binary_j = format(j, f'0{numadd}b')
                result_j = 1
                binary_k = format(k, f'0{numadd}b')
                result_k = 1
                for addenda in range(numadd):
                    result_j *= int(binary_j[addenda])
                    result_k *= int(binary_k[addenda])
                difference = result_j ^ result_k
                if difference == m:
                    count += 1
            ddt_table.append(count)

    return ddt_table


def cp_xor_linear_probability_lat(numadd):
    """
    Return the lat of the AND operation CP xor linear probability.

    INPUT:

    - ``numadd`` -- **integer**; the number of addenda

    EXAMPLES::

        sage: from claasp.components.and_component import cp_xor_linear_probability_lat
        sage: cp_xor_linear_probability_lat(2)
        [2, 1, 0, 1, 0, 1, 0, -1]
    """
    lat = []
    for full_mask in range(2 ** (numadd + 1)):
        num_of_matches = 0
        for values in range(2 ** numadd):
            full_values = values << 1
            bit_of_values = (values >> i & 1 for i in range(numadd))
            full_values ^= 0 not in bit_of_values
            equation = full_values & full_mask
            addenda = (equation >> i & 1 for i in range(numadd + 1))
            num_of_matches += (sum(addenda) % 2 == 0)
        lat.append(num_of_matches - (2 ** (numadd - 1)))

    return lat


class AND(MultiInputNonlinearLogicalOperator):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size):
        super().__init__(current_round_number, current_round_number_of_components,
                         input_id_links, input_bit_positions, output_bit_size, 'and')

    def algebraic_polynomials(self, model):
        """
        Return polynomials for Boolean AND.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: and_component = fancy.get_component_from_id("and_0_8")
            sage: algebraic = AlgebraicModel(fancy)
            sage: and_component.algebraic_polynomials(algebraic)
            [and_0_8_x0*and_0_8_x12 + and_0_8_y0,
             and_0_8_x1*and_0_8_x13 + and_0_8_y1,
             and_0_8_x2*and_0_8_x14 + and_0_8_y2,
             and_0_8_x3*and_0_8_x15 + and_0_8_y3,
             and_0_8_x4*and_0_8_x16 + and_0_8_y4,
             and_0_8_x5*and_0_8_x17 + and_0_8_y5,
             and_0_8_x6*and_0_8_x18 + and_0_8_y6,
             and_0_8_x7*and_0_8_x19 + and_0_8_y7,
             and_0_8_x8*and_0_8_x20 + and_0_8_y8,
             and_0_8_x9*and_0_8_x21 + and_0_8_y9,
             and_0_8_x10*and_0_8_x22 + and_0_8_y10,
             and_0_8_x11*and_0_8_x23 + and_0_8_y11]
        """
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        word_size = noutputs
        ring_R = model.ring()
        input_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        words_vars = [list(map(ring_R, input_vars))[i:i + word_size] for i in range(0, ninputs, word_size)]

        x = [ring_R.one() for _ in range(noutputs)]
        for word_vars in words_vars:
            for i in range(noutputs):
                x[i] *= word_vars[i]
        y = list(map(ring_R, output_vars))

        return [y[i] + x[i] for i in range(noutputs)]

    def cp_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for AND component.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher()
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.cp_constraints()
            ([],
             ['constraint and_0_8[0] = xor_0_7[0] * key[12];',
              ...
              'constraint and_0_8[11] = xor_0_7[11] * key[23];'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = []
        for i in range(output_size):
            operation = ' * '.join(all_inputs[i::output_size])
            new_constraint = f'constraint {output_id_link}[{i}] = {operation};'
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def cp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists declarations and constraints for the probability of AND component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: fancy = FancyBlockCipher()
            sage: cp = MznModel(fancy)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.cp_xor_linear_mask_propagation_constraints(cp)
            (['array[0..23] of var 0..1:and_0_8_i;',
              'array[0..11] of var 0..1:and_0_8_o;'],
             ['constraint table([and_0_8_i[0]]++[and_0_8_i[12]]++[and_0_8_o[0]]++[p[0]],and2inputs_LAT);',
               ...
              'constraint table([and_0_8_i[11]]++[and_0_8_i[23]]++[and_0_8_o[11]]++[p[11]],and2inputs_LAT);'])
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        cp_declarations = []
        cp_constraints = []
        num_add = self.description[1]
        input_len = input_size // num_add
        cp_declarations.append(f'array[0..{input_size - 1}] of var 0..1:{output_id_link}_i;')
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1:{output_id_link}_o;')
        model.component_and_probability[output_id_link] = 0
        probability = []
        for i in range(output_size):
            new_constraint = f'constraint table('
            for j in range(num_add):
                new_constraint = new_constraint + f'[{output_id_link}_i[{i + input_len * j}]]++'
            if model.float_and_lat_values:
                cp_declarations.append(f'var :p_{output_id_link}_{i};')
                new_constraint = \
                    new_constraint + f'[{output_id_link}_o[{i}]]++[p_{output_id_link}_{i}],and{num_add}inputs_LAT);'
                cp_constraints.append(new_constraint)
                for k in range(len(model.float_and_lat_values)):
                    rounded_float = round(float(model.float_and_lat_values[k]), 2)
                    cp_constraints.append(
                        f'constraint if p_{output_id_link}_{i} == {1000 + k} then p[{model.c}]={rounded_float} else '
                        f'p[{model.c}]=p_{output_id_link}_{i} endif;')
            else:
                new_constraint = new_constraint + f'[{output_id_link}_o[{i}]]++[p[{model.c}]],and{num_add}inputs_LAT);'
                cp_constraints.append(new_constraint)
            probability.append(model.c)
            model.c += 1
        model.component_and_probability[output_id_link] = probability
        result = cp_declarations, cp_constraints
        return result

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for AND component
        in the bitwise deterministic truncated XOR differential model.

        INPUTS:

        - ``component`` -- *dict*, the AND component in Graph Representation

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: cipher = FancyBlockCipher(number_of_rounds=20)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: and_component = cipher.component_from(0,8)
            sage: variables, constraints = and_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[xor_0_7_0]', x_0),
            ('x_class[xor_0_7_1]', x_1),
            ...
            ('x_class[and_0_8_10]', x_34),
            ('x_class[and_0_8_11]', x_35)]
            sage: constraints
            [x_0 + x_12 <= 4 - 4*x_36,
            1 - 4*x_36 <= x_0 + x_12,
            ...
            x_35 <= 2 + 2*x_47,
            2 <= x_35 + 2*x_47]

        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        output_bit_size = self.output_bit_size
        component_id = self.id
        model.non_linear_component_id.append(component_id)

        number_of_inputs = self.description[1]
        input_bit_size = int(self.input_bit_size / number_of_inputs)

        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []

        a = [[x_class[input_vars[i + chunk * input_bit_size]] for chunk in range(number_of_inputs)] for i in
             range(input_bit_size)]
        b = [x_class[output_vars[i]] for i in range(output_bit_size)]

        upper_bound = model._model.get_max(x_class)

        for i in range(output_bit_size):
            input_sum = sum([a[i][chunk] for chunk in range(number_of_inputs)])
            # if d_leq == 1 if sum(a_i) <= 0
            d_leq, c_leq = milp_utils.milp_leq(model, input_sum, 0, number_of_inputs * upper_bound)
            constraints += c_leq
            # if all ai == 0, then b[i] = 0, else b[i] = 2
            constraints += milp_utils.milp_if_then_else(d_leq, [b[i] == 0], [b[i] == 2], upper_bound)

        return variables, constraints

    def generic_sign_linear_constraints(self, inputs, outputs):
        """
        Return the constraints for finding the sign of an AND component.

        INPUT:

        - ``inputs`` -- **list**; a list representing the inputs to the AND
        - ``outputs`` -- **list**; a list representing the output to the AND

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.components.and_component import AND
            sage: simon = SimonBlockCipher()
            sage: and_component = simon.component_from(0,4)
            sage: input = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            sage: output = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            sage: and_component.generic_sign_linear_constraints(input, output)
            1
        """
        sign = +1
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        and_LAT = [[[1, 1], [0, 1]], [[0, 1], [0, -1]]]
        for i in range(output_size):
            sign = sign * and_LAT[inputs[i]][inputs[input_size // 2 + i]][outputs[i]]

        return sign

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = bit_vector_AND([{",".join(params)} ], {self.description[1]}, {self.output_bit_size})']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} =byte_vector_AND({params})']

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for AND operation in SAT CIPHER model.

        This method support AND operation using more than two operands.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.sat_constraints()
            (['and_0_8_0',
              'and_0_8_1',
              'and_0_8_2',
              ...
              '-and_0_8_11 xor_0_7_11',
              '-and_0_8_11 key_23',
              'and_0_8_11 -xor_0_7_11 -key_23'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_and(output_bit_ids[i], input_bit_ids[i::output_bit_len]))

        return output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing AND operation FOR SMT CIPHER model.

        This method support AND operation using more than two operands.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: and_component = fancy.component_from(0, 8)
            sage: and_component.smt_constraints()
            (['and_0_8_0',
              'and_0_8_1',
              ...
              'and_0_8_10',
              'and_0_8_11'],
             ['(assert (= and_0_8_0 (and xor_0_7_0 key_12)))',
              '(assert (= and_0_8_1 (and xor_0_7_1 key_13)))',
              ...
              '(assert (= and_0_8_10 (and xor_0_7_10 key_22)))',
              '(assert (= and_0_8_11 (and xor_0_7_11 key_23)))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            operation = smt_utils.smt_and(input_bit_ids[i::output_bit_len])
            equation = smt_utils.smt_equivalent((output_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints
