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


class Or(MultiInputNonlinearLogicalOperator):
    """
    Construct an OR component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.

    NOTE:

        The number of operands is automatically inferred as
        ``sum(len(p) for p in input_bit_positions) / output_bit_size``.
        For example, two input groups of 2 bits each with ``output_bit_size=2`` give a 2-input OR;
        three input groups of 2 bits each give a 3-input OR.

    EXAMPLES::

        sage: from claasp.components.or_component import Or
        sage: component = Or(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2)
        sage: print(component.id)
        or_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['OR', 2]
        sage: component3 = Or(0, 1, ['a', 'b', 'c'], [[0, 1], [0, 1], [0, 1]], 2)
        sage: print(component3.description)  # 6 total bits / output_bit_size 2 = 3 operands
        ['OR', 3]
    """
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

            sage: from claasp.ciphers.single_component_ciphers.or_cipher import OrCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = OrCipher(word_bit_size=4, number_of_inputs=2)
            sage: or_component = cipher.component_from_id("or_0_0")
            sage: algebraic = AlgebraicModel(cipher)
            sage: or_component.algebraic_polynomials(algebraic)
            [or_0_0_x0*or_0_0_x4 + or_0_0_y0 + or_0_0_x4 + or_0_0_x0,
             or_0_0_x1*or_0_0_x5 + or_0_0_y1 + or_0_0_x5 + or_0_0_x1,
             or_0_0_x2*or_0_0_x6 + or_0_0_y2 + or_0_0_x6 + or_0_0_x2,
             or_0_0_x3*or_0_0_x7 + or_0_0_y3 + or_0_0_x7 + or_0_0_x3]

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

            sage: from claasp.components.or_component import Or
            sage: or_component = Or(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2)
            sage: or_component.cp_constraints()
            (['array[0..1] of var 0..1: or_0_0;',
            'array[0..1] of var 0..1:pre_or_0_0_0;',
            'array[0..1] of var 0..1:pre_or_0_0_1;'],
            ['constraint pre_or_0_0_0[0]=input1[0];',
            'constraint pre_or_0_0_0[1]=input1[1];',
            'constraint pre_or_0_0_1[0]=input2[0];',
            'constraint pre_or_0_0_1[1]=input2[1];',
            'constraint or(pre_or_0_0_0, pre_or_0_0_1, or_0_0);'])
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

            sage: from claasp.ciphers.single_component_ciphers.or_cipher import OrCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: cipher = OrCipher(word_bit_size=4, number_of_inputs=2)
            sage: or_component = cipher.component_from_id("or_0_0")
            sage: cp = MznModel(cipher)
            sage: declarations, constraints = or_component.cp_xor_linear_mask_propagation_constraints(cp)
            sage: declarations
            ['array[0..3] of var 0..400: p_or_0_0;',
             'array[0..7] of var 0..1:or_0_0_i;',
             'array[0..3] of var 0..1:or_0_0_o;']
            sage: constraints
            ['constraint table([or_0_0_i[0]]++[or_0_0_i[4]]++[or_0_0_o[0]]++[p_or_0_0[0]],and2inputs_LAT);',
             'constraint table([or_0_0_i[1]]++[or_0_0_i[5]]++[or_0_0_o[1]]++[p_or_0_0[1]],and2inputs_LAT);',
             'constraint table([or_0_0_i[2]]++[or_0_0_i[6]]++[or_0_0_o[2]]++[p_or_0_0[2]],and2inputs_LAT);',
             'constraint table([or_0_0_i[3]]++[or_0_0_i[7]]++[or_0_0_o[3]]++[p_or_0_0[3]],and2inputs_LAT);',
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

            sage: from claasp.components.or_component import Or
            sage: or_component = Or(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2)
            sage: input = [0, 0, 0, 1]
            sage: output = [0, 1]
            sage: or_component.generic_sign_linear_constraints(input, output)
            1
            sage: from claasp.components.or_component import Or
            sage: or_component = Or(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2)
            sage: input = [0, 0, 0, 1]
            sage: output = [1, 1]
            sage: or_component.generic_sign_linear_constraints(input, output)
            -1
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

            sage: from claasp.components.or_component import Or
            sage: component = Or(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2)
            sage: component.sat_constraints()
            (['or_0_0_0', 'or_0_0_1'],
            ['or_0_0_0 -input1_0',
            'or_0_0_0 -input2_0',
            '-or_0_0_0 input1_0 input2_0',
            'or_0_0_1 -input1_1',
            'or_0_0_1 -input2_1',
            '-or_0_0_1 input1_1 input2_1'])
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

            sage: from claasp.components.or_component import Or
            sage: component = Or(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2)
            sage: component.smt_constraints()
            (['or_0_0_0', 'or_0_0_1'],
            ['(assert (= or_0_0_0 (or input1_0 input2_0)))',
            '(assert (= or_0_0_1 (or input1_1 input2_1)))'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            operation = smt_utils.smt_or(input_bit_ids[i::output_bit_len])
            equation = smt_utils.smt_equivalent((output_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints
