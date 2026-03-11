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
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            "or",
        )

    def algebraic_polynomials(self, model):
        """
        Return polynomials for Boolean OR.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.toys.or_block_cipher import OrBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = OrBlockCipher(block_bit_size=32)
            sage: or_component = cipher.get_component_from_id("or_0_0")
            sage: algebraic = AlgebraicModel(cipher)
            sage: polys = or_component.algebraic_polynomials(algebraic)
            sage: len(polys)
            32
            sage: polys[0]
            or_0_0_x0*or_0_0_x32 + or_0_0_y0 + or_0_0_x32 + or_0_0_x0

        """
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        ors_number = self.description[1] - 1
        word_size = noutputs
        ring_R = model.ring()
        input_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]
        output_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]
        words_vars = [list(map(ring_R, input_vars))[i : i + word_size] for i in range(0, ninputs, word_size)]

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
                all_inputs.append(f"{input_id_link[i]}[{input_bit_positions[i][j]}]")
        total_input_len = len(all_inputs)
        input_len = total_input_len // num_add
        cp_declarations.append(f"array[0..{self.output_bit_size - 1}] of var 0..1: {output_id_link};")
        for i in range(num_add):
            cp_declarations.append(f"array[0..{input_len - 1}] of var 0..1:pre_{output_id_link}_{i};")
            for j in range(input_len):
                cp_constraints.append(f"constraint pre_{output_id_link}_{i}[{j}]={all_inputs[i * input_len + j]};")
        for i in range(num_add - 2):
            cp_declarations.append(f"array[0..{self.output_bit_size - 1}] of var 0..1:temp_{output_id_link}_{i};")
        if num_add == 2:
            cp_constraints.append(f"constraint or(pre_{output_id_link}_0, pre_{output_id_link}_1, {output_id_link});")
        elif num_add > 2:
            cp_constraints.append(
                f"constraint or(pre_{output_id_link}_0, pre_{output_id_link}_1, temp_{output_id_link}_0);"
            )
            for i in range(1, num_add - 2):
                cp_constraints.append(
                    f"constraint or(pre_{output_id_link}_{i + 1}, temp_{output_id_link}_{i - 1}, "
                    f"temp_{output_id_link}_{i});"
                )
            cp_constraints.append(
                f"constraint or(pre_{output_id_link}_{num_add - 1}, temp_{output_id_link}_{num_add - 3},"
                f"{output_id_link});"
            )

        return cp_declarations, cp_constraints

    def cp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of declarations and constraints for the probability of OR for CP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

                        sage: from claasp.ciphers.toys.or_block_cipher import OrBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
                        sage: cipher = OrBlockCipher(block_bit_size=32)
                        sage: or_component = cipher.component_from(0, 0)
                        sage: cp = MznModel(cipher)
            sage: declarations, constraints = or_component.cp_xor_linear_mask_propagation_constraints(cp)
            sage: declarations
                        ['array[0..31] of var 0..3200: p_or_0_0;',
                         'array[0..63] of var 0..1:or_0_0_i;',
                         'array[0..31] of var 0..1:or_0_0_o;']
                        sage: constraints
                        ['constraint table([or_0_0_i[0]]++[or_0_0_i[32]]++[or_0_0_o[0]]++[p_or_0_0[0]],and2inputs_LAT);',
                        'constraint table([or_0_0_i[1]]++[or_0_0_i[33]]++[or_0_0_o[1]]++[p_or_0_0[1]],and2inputs_LAT);',
            ...
                        'constraint table([or_0_0_i[31]]++[or_0_0_i[63]]++[or_0_0_o[31]]++[p_or_0_0[31]],and2inputs_LAT);',
                        'constraint p[0] = sum(p_or_0_0);']

        """
        cp_declarations = [
            f"array[0..{self.output_bit_size - 1}] of var 0..{100 * self.output_bit_size}: p_{self.id};",
            f"array[0..{self.input_bit_size - 1}] of var 0..1:{self.id}_i;",
            f"array[0..{self.output_bit_size - 1}] of var 0..1:{self.id}_o;",
        ]
        cp_constraints = []
        num_add = self.description[1]
        input_len = self.input_bit_size // num_add
        model.component_and_probability[self.id] = 0
        p_count = 0
        for i in range(self.output_bit_size):
            inputs = "++".join(f"[{self.id}_i[{i + input_len * j}]]" for j in range(num_add))
            cp_constraint = (
                f"constraint table({inputs}++[{self.id}_o[{i}]]++[p_{self.id}[{p_count}]],and{num_add}inputs_LAT);"
            )
            cp_constraints.append(cp_constraint)
            p_count = p_count + 1
        cp_constraints.append(f"constraint p[{model.c}] = sum(p_{self.id});")
        model.component_and_probability[self.id] = model.c
        model.c = model.c + 1

        return cp_declarations, cp_constraints

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
        return [f"  {self.id} = bit_vector_OR([{','.join(params)} ], {self.description[1]}, {self.output_bit_size})"]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_OR({params})"]

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing OR for SAT CIPHER model

        This method translates in CNF the constraint ``z = Or(x, y)``. It becomes in prefixed notation:
        ``And(Or(z, Not(x)), Or(z, Not(y)), Or(x, y, Not(z)))``.
        This method support OR operation using more than two inputs.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

                        sage: from claasp.components.or_component import OR
                        sage: or_component = OR(0, 0, ['input1', 'input2'], [list(range(32)), list(range(32))], 32)
            sage: or_component.sat_constraints()
                        (['or_0_0_0',
                            'or_0_0_1',
              ...
                            'or_0_0_30',
                            'or_0_0_31'],
                         ['or_0_0_0 -input1_0',
                            'or_0_0_0 -input2_0',
              ...
                            'or_0_0_31 -input2_31',
                            '-or_0_0_31 input1_31 input2_31'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_or(output_bit_ids[i], input_bit_ids[i::output_bit_len]))

        return output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing OR for SMT CIPHER model

        Since the OR operation is part of the SMT-LIB formalism, the operation can be modeled using the corresponding
        builtin operation, e.g. ``z = Or(x, y)`` becomes ``(assert (= z (or x y)))``.
        This method support OR operation using more than two inputs.

        INPUT:

        - None

        EXAMPLES::

                        sage: from claasp.components.or_component import OR
                        sage: or_component = OR(0, 0, ['input1', 'input2'], [list(range(32)), list(range(32))], 32)
            sage: or_component.smt_constraints()
                        (['or_0_0_0',
                            'or_0_0_1',
              ...
                            'or_0_0_30',
                            'or_0_0_31'],
                         ['(assert (= or_0_0_0 (or input1_0 input2_0)))',
                            '(assert (= or_0_0_1 (or input1_1 input2_1)))',
              ...
                            '(assert (= or_0_0_30 (or input1_30 input2_30)))',
                            '(assert (= or_0_0_31 (or input1_31 input2_31)))'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            operation = smt_utils.smt_or(input_bit_ids[i::output_bit_len])
            equation = smt_utils.smt_equivalent((output_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints
