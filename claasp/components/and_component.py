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


from claasp.cipher_modules.models.milp.utils import utils as milp_utils
from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator


def cp_twoterms(model, inp1, inp2, out, cp_constraints):
    cp_constraints.append(
        f"constraint Ham_weight(Andz({inp1}, {inp2}, {out})) == 0 /\\ p[{model.c}] = Ham_weight(Or({inp1}, {inp2}));"
    )
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
                binary_j = f"{j:0{numadd}b}"
                result_j = 1
                binary_k = f"{k:0{numadd}b}"
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
        for values in range(2**numadd):
            full_values = values << 1
            bit_of_values = (values >> i & 1 for i in range(numadd))
            full_values ^= 0 not in bit_of_values
            equation = full_values & full_mask
            addenda = (equation >> i & 1 for i in range(numadd + 1))
            num_of_matches += sum(addenda) % 2 == 0
        lat.append(num_of_matches - (2 ** (numadd - 1)))

    return lat


class And(MultiInputNonlinearLogicalOperator):
    """
    Construct an AND component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.

    NOTE:

        The number of operands is automatically inferred as
        ``sum(len(p) for p in input_bit_positions) / output_bit_size``.
        For example, two input groups of 2 bits each with ``output_bit_size=2`` give a 2-input AND;
        three input groups of 2 bits each give a 3-input AND.

    EXAMPLES::

        sage: from claasp.components.and_component import And
        sage: component = And(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2)
        sage: print(component.id)
        and_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['AND', 2]
        sage: component3 = And(0, 1, ['a', 'b', 'c'], [[0, 1], [0, 1], [0, 1]], 2)
        sage: print(component3.description)  # 6 total bits / output_bit_size 2 = 3 operands
        ['AND', 3]
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
            "and",
        )

    def algebraic_polynomials(self, model):
        """
        Return polynomials for Boolean AND.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = AndCipher(word_bit_size=4, number_of_inputs=2)
            sage: and_component = cipher.component_from_id("and_0_0")
            sage: algebraic = AlgebraicModel(cipher)
            sage: and_component.algebraic_polynomials(algebraic)
            [and_0_0_x0*and_0_0_x4 + and_0_0_y0,
             and_0_0_x1*and_0_0_x5 + and_0_0_y1,
             and_0_0_x2*and_0_0_x6 + and_0_0_y2,
             and_0_0_x3*and_0_0_x7 + and_0_0_y3]
        """
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        word_size = noutputs
        ring_R = model.ring()
        input_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]
        output_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]
        words_vars = [list(map(ring_R, input_vars))[i : i + word_size] for i in range(0, ninputs, word_size)]

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

            sage: from claasp.components.and_component import And
            sage: and_component = And(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2)
            sage: and_component.cp_constraints()
            ([],
             ['constraint and_0_0[0] = input1[0] * input2[0];',
              'constraint and_0_0[1] = input1[1] * input2[1];'])
        """
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_constraints = []
        for i in range(self.output_bit_size):
            operation = " * ".join(all_inputs[i :: self.output_bit_size])
            cp_constraint = f"constraint {self.id}[{i}] = {operation};"
            cp_constraints.append(cp_constraint)

        return cp_declarations, cp_constraints

    def cp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists declarations and constraints for the probability of AND component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
            sage: cp = MznModel(cipher)
            sage: and_component = cipher.component_from_id('and_0_0')
            sage: and_component.cp_xor_linear_mask_propagation_constraints(cp)
            (['array[0..23] of var 0..1:and_0_0_i;',
              'array[0..11] of var 0..1:and_0_0_o;'],
             ['constraint table([and_0_0_i[0]]++[and_0_0_i[12]]++[and_0_0_o[0]]++[p[0]],and2inputs_LAT);',
               ...
              'constraint table([and_0_0_i[11]]++[and_0_0_i[23]]++[and_0_0_o[11]]++[p[11]],and2inputs_LAT);'])
        """
        output_id_link = self.id
        cp_declarations = []
        cp_constraints = []
        num_add = self.description[1]
        input_len = self.input_bit_size // num_add
        cp_declarations.append(f"array[0..{self.input_bit_size - 1}] of var 0..1:{output_id_link}_i;")
        cp_declarations.append(f"array[0..{self.output_bit_size - 1}] of var 0..1:{output_id_link}_o;")
        model.component_and_probability[output_id_link] = 0
        probability = []
        for i in range(self.output_bit_size):
            new_constraint = "constraint table("
            for j in range(num_add):
                new_constraint = new_constraint + f"[{output_id_link}_i[{i + input_len * j}]]++"
            if model.float_and_lat_values:
                cp_declarations.append(f"var :p_{output_id_link}_{i};")
                new_constraint = (
                    new_constraint + f"[{output_id_link}_o[{i}]]++[p_{output_id_link}_{i}],and{num_add}inputs_LAT);"
                )
                cp_constraints.append(new_constraint)
                for k in range(len(model.float_and_lat_values)):
                    rounded_float = round(float(model.float_and_lat_values[k]), 2)
                    cp_constraints.append(
                        f"constraint if p_{output_id_link}_{i} == {1000 + k} then p[{model.c}]={rounded_float} else "
                        f"p[{model.c}]=p_{output_id_link}_{i} endif;"
                    )
            else:
                new_constraint = new_constraint + f"[{output_id_link}_o[{i}]]++[p[{model.c}]],and{num_add}inputs_LAT);"
                cp_constraints.append(new_constraint)
            probability.append(model.c)
            model.c += 1
        model.component_and_probability[output_id_link] = probability

        return cp_declarations, cp_constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for AND component
        in the bitwise deterministic truncated XOR differential model.

        INPUTS:

        - ``component`` -- *dict*, the AND component in Graph Representation

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: and_component = cipher.component_from_id('and_0_0')
            sage: variables, constraints = and_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[plaintext_0]', x_0),
            ('x_class[plaintext_1]', x_1),
            ...
            ('x_class[and_0_0_10]', x_34),
            ('x_class[and_0_0_11]', x_35)]
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

        a = [
            [x_class[input_vars[i + chunk * input_bit_size]] for chunk in range(number_of_inputs)]
            for i in range(input_bit_size)
        ]
        b = [x_class[output_vars[i]] for i in range(output_bit_size)]

        upper_bound = model._model.get_max(x_class)

        for i in range(output_bit_size):
            input_sum = sum(a[i][chunk] for chunk in range(number_of_inputs))
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

            sage: from claasp.components.and_component import And
            sage: and_component = And(0, 0, ['plaintext', 'key'], [list(range(16)), list(range(16))], 16)
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
        return [f"  {self.id} = bit_vector_AND([{','.join(params)} ], {self.description[1]}, {self.output_bit_size})"]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_AND({params})"]

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing AND for SAT CIPHER model

        This method translates in CNF the constraint ``z = And(x, y)``. In prefixed notation, it becomes:
        ``And(Or(x, Not(z)), Or(y, Not(z)), Or(z, Not(x), Not(y)))``.
        This method supports AND operation using more than two inputs.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.and_component import And
            sage: and_component = And(0, 0, ['plaintext', 'key'], [list(range(2)), list(range(2))], 2)
            sage: and_component.sat_constraints()
            (['and_0_0_0', 'and_0_0_1'],
            ['-and_0_0_0 plaintext_0',
            '-and_0_0_0 key_0',
            'and_0_0_0 -plaintext_0 -key_0',
            '-and_0_0_1 plaintext_1',
            '-and_0_0_1 key_1',
            'and_0_0_1 -plaintext_1 -key_1'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()
        constraints = []
        for i, output_bit_id in enumerate(output_bit_ids):
            constraints.extend(sat_utils.cnf_and(output_bit_id, input_bit_ids[i :: self.output_bit_size]))

        return output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing AND for SMT CIPHER model

        Since the AND operation is part of the SMT-LIB formalism, the operation can be modeled using the corresponding
        builtin operation, e.g. ``z = And(x, y)`` becomes ``(assert (= z (and x y)))``.
        This method support AND operation using more than two inputs.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.and_component import And
            sage: and_component = And(0, 0, ['plaintext', 'key'], [list(range(2)), list(range(2))], 2)
            sage: and_component.smt_constraints()
            (['and_0_0_0', 'and_0_0_1'],
            ['(assert (= and_0_0_0 (and plaintext_0 key_0)))',
            '(assert (= and_0_0_1 (and plaintext_1 key_1)))'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()
        constraints = []
        for i, output_bit_id in enumerate(output_bit_ids):
            operation = smt_utils.smt_and(input_bit_ids[i :: self.output_bit_size])
            equation = smt_utils.smt_equivalent((output_bit_id, operation))
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_quasidifferential_propagation_constraints(
        self,
        model,
    ):
        """
        Return SMT constraints for AND quasidifferential propagation.

        Implements Theorem 5.1 of Beyne & Rijmen for a single bitwise
        AND of 2 n-bit operands (a, b) -> c, extended bit-independently
        via Theorem 3.2 (2) ("boxed maps": AND acts on each bit
        independently, so its QDT is the tensor product of the 1-bit
        QDTs).

        Only 2-input AND is currently supported -- this is what Simon
        actually uses, and Theorem 5.1 itself is stated for a single
        pairwise AND. An n>2 input AND would need its own derivation,
        so this deliberately raises NotImplementedError rather than
        guessing; build_xor_quasidifferential_trail_model already
        catches that and skips the component with a clear message.

        Per bit i (a_i, b_i -> c_i; masks u_i, v_i on a, b and w_i on c):

            c_i => (a_i or b_i)
            (u_i or v_i) => (a_i or b_i or w_i)
            (a_i and u_i) xor (b_i and v_i) == (c_i and w_i)

        Local weight per bit is exactly (a_i or b_i or w_i): the
        theorem's weight formula wt(a|b) + wt(w & ~a & ~b) reduces to
        this single per-bit OR, since the two terms are mutually
        exclusive at each bit position (if a_i|b_i is true the first
        term contributes 1 and the second is forced to 0 by ~a&~b;
        if a_i|b_i is false the first term is 0 and the second equals
        w_i exactly).

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = AndCipher(word_bit_size=2, number_of_inputs=2)
            sage: and_component = cipher.component_from_id('and_0_0')
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: variables, constraints = and_component.smt_xor_quasidifferential_propagation_constraints(smt)
            sage: variables
            ['and_0_0_0',
             'and_0_0_1',
             'qdt_and_0_0_0',
             'qdt_and_0_0_1',
             'hw_qdt_and_0_0_0',
             'hw_qdt_and_0_0_1']
            sage: len(constraints)
            8
            sage: constraints[0]
            '(assert (=> and_0_0_0 (or plaintext_0 key_0)))'
            sage: constraints[3]
            '(assert (= hw_qdt_and_0_0_0 (or plaintext_0 key_0 qdt_and_0_0_0)))'
        """

        num_operands = self.description[1]

        if num_operands != 2:
            raise NotImplementedError(
                f"{self.id}: quasidifferential propagation for AND is "
                f"only implemented for 2 operands (Theorem 5.1 of "
                f"Beyne & Rijmen); got {num_operands}."
            )

        word_size = self.output_bit_size

        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()

        qdt_input_bit_ids = [f"qdt_{bit_id}" for bit_id in input_bit_ids]

        qdt_output_bit_ids = [f"qdt_{bit_id}" for bit_id in output_bit_ids]

        a_ids = input_bit_ids[:word_size]
        b_ids = input_bit_ids[word_size:]

        u_ids = qdt_input_bit_ids[:word_size]
        v_ids = qdt_input_bit_ids[word_size:]

        c_ids = output_bit_ids
        w_ids = qdt_output_bit_ids

        weight_bit_ids = [f"hw_qdt_{self.id}_{i}" for i in range(word_size)]

        constraints = []

        for i in range(word_size):
            a, b, c = a_ids[i], b_ids[i], c_ids[i]
            u, v, w = u_ids[i], v_ids[i], w_ids[i]

            # c_i => (a_i or b_i)
            validity_1 = smt_utils.smt_implies(
                c,
                smt_utils.smt_or([a, b]),
            )
            constraints.append(smt_utils.smt_assert(validity_1))

            # (u_i or v_i) => (a_i or b_i or w_i)
            validity_2 = smt_utils.smt_implies(
                smt_utils.smt_or([u, v]),
                smt_utils.smt_or([a, b, w]),
            )
            constraints.append(smt_utils.smt_assert(validity_2))

            # (a_i and u_i) xor (b_i and v_i) == (c_i and w_i)
            validity_3 = smt_utils.smt_equivalent(
                [
                    smt_utils.smt_xor(
                        [
                            smt_utils.smt_and([a, u]),
                            smt_utils.smt_and([b, v]),
                        ]
                    ),
                    smt_utils.smt_and([c, w]),
                ]
            )
            constraints.append(smt_utils.smt_assert(validity_3))

            # Local weight bit: hw_qdt_{id}_{i} := (a_i or b_i or w_i)
            weight_definition = smt_utils.smt_equivalent(
                [
                    weight_bit_ids[i],
                    smt_utils.smt_or([a, b, w]),
                ]
            )
            constraints.append(smt_utils.smt_assert(weight_definition))

        variables = output_bit_ids + qdt_output_bit_ids + weight_bit_ids

        return (
            variables,
            constraints,
        )
