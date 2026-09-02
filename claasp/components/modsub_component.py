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
from claasp.components.modular_component import Modular


def cp_twoterms(input_1, input_2, out, component_name, input_length, cp_constraints, cp_declarations):
    cp_declarations.append(f"array[0..{input_length - 1}] of var 0..1:pre_minus_{input_2};")
    cp_declarations.append(f"array[0..{input_length - 1}] of var 0..1:minus_{input_2};")
    for i in range(input_length):
        cp_constraints.append(f"constraint pre_minus_{input_2}[{i}]=({input_2}[{i}] + 1) mod 2;")
    cp_constraints.append(f"constraint modadd(pre_minus_{input_2}, constant_{component_name}, minus_{input_2});")
    cp_constraints.append(f"constraint modadd({input_1},minus_{input_2},{out});")

    return cp_declarations, cp_constraints


def sat_generate_ids_for_modsub(component):
    input_bit_ids = component._generate_input_ids()
    lhs_input_bit_ids = input_bit_ids[: component.output_bit_size]
    rhs_input_bit_ids = input_bit_ids[component.output_bit_size :]
    output_bit_ids = component._generate_output_ids()
    temp_carry_bit_ids = [f"temp_carry_{rhs_input_bit_id}" for rhs_input_bit_id in rhs_input_bit_ids[:-1]]
    temp_input_bit_ids = [f"temp_input_{rhs_input_bit_id}" for rhs_input_bit_id in rhs_input_bit_ids]
    carry_bit_ids = [f"carry_{output_bit_id}" for output_bit_id in output_bit_ids[:-1]]

    return output_bit_ids, temp_carry_bit_ids, temp_input_bit_ids, carry_bit_ids, lhs_input_bit_ids, rhs_input_bit_ids


class ModSub(Modular):
    """
    Construct a modular subtraction component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``modulus`` -- **integer**; modulus used by modular arithmetic operations. Must be greater than ``0``.

    NOTE:

        The number of operands is automatically inferred as
        ``sum(len(p) for p in input_bit_positions) / output_bit_size``.
        However, **only 2 operands are supported** by the bit-vector evaluator and the SAT/CMS
        constraint methods (attempting more will raise an ``AssertionError`` at runtime).
        The algebraic model handles more than 2 operands via left-to-right sequential subtraction:
        ``a0 - a1 - a2 - ...`` (i.e. ``((a0 - a1) - a2) - ...``).

    EXAMPLES::

        sage: from claasp.components.modsub_component import ModSub
        sage: component = ModSub(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
        sage: print(component.id)
        modsub_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)  # 4 total bits / output_bit_size 2 = 2 operands
        ['MODSUB', 2, 2]
        sage: component3 = ModSub(0, 1, ['a', 'b', 'c'], [[0, 1], [0, 1], [0, 1]], 2, 4)
        sage: print(component3.description)  # 6 total bits / output_bit_size 2 = 3 operands
        ['MODSUB', 3, 4]
    """

    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        modulus,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            "modsub",
            modulus,
        )

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials representing Modular subtraction operation

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

                sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
                sage: from claasp.ciphers.single_component_ciphers.modsub_cipher import ModsubCipher
                sage: cipher = ModsubCipher()
                sage: modsub_component = cipher.component_from_id('modsub_0_0')
                sage: algebraic = AlgebraicModel(cipher)
                sage: modsub_component.algebraic_polynomials(algebraic)
                [modsub_0_0_b0_0,
                modsub_0_0_b0_0 + modsub_0_0_y0 + modsub_0_0_x4 + modsub_0_0_x0,
                modsub_0_0_x4*modsub_0_0_b0_0 + modsub_0_0_x0*modsub_0_0_b0_0 + modsub_0_0_x0*modsub_0_0_x4 + modsub_0_0_b0_1 + modsub_0_0_b0_0 + modsub_0_0_x4,
                modsub_0_0_b0_1 + modsub_0_0_y1 + modsub_0_0_x5 + modsub_0_0_x1,
                modsub_0_0_x5*modsub_0_0_b0_1 + modsub_0_0_x1*modsub_0_0_b0_1 + modsub_0_0_x1*modsub_0_0_x5 + modsub_0_0_b0_2 + modsub_0_0_b0_1 + modsub_0_0_x5,
                modsub_0_0_b0_2 + modsub_0_0_y2 + modsub_0_0_x6 + modsub_0_0_x2,
                modsub_0_0_x6*modsub_0_0_b0_2 + modsub_0_0_x2*modsub_0_0_b0_2 + modsub_0_0_x2*modsub_0_0_x6 + modsub_0_0_b0_3 + modsub_0_0_b0_2 + modsub_0_0_x6,
                modsub_0_0_b0_3 + modsub_0_0_y3 + modsub_0_0_x7 + modsub_0_0_x3]

        """
        component_id = self.id
        ninput_words = self.description[1]
        nsubtractions = ninput_words - 1
        ninput_bits = self.input_bit_size
        noutput_bits = word_size = self.output_bit_size

        input_vars = [f"{component_id}_{model.input_postfix}{i}" for i in range(ninput_bits)]
        output_vars = [f"{component_id}_{model.output_postfix}{i}" for i in range(noutput_bits)]
        borrows_vars = [[f"{component_id}_b{n}_{i}" for i in range(word_size)] for n in range(nsubtractions)]
        aux_outputs_vars = [[f"{component_id}_o{n}_{i}" for i in range(word_size)] for n in range(nsubtractions - 1)]

        ring_R = model.ring()
        input_vars = list(map(ring_R, input_vars))
        output_vars = list(map(ring_R, output_vars))
        borrows_vars = [list(map(ring_R, borrow_vars)) for borrow_vars in borrows_vars]
        aux_outputs_vars = [list(map(ring_R, aux_output_vars)) for aux_output_vars in aux_outputs_vars]

        def borrow_polynomial(xi, yi, bi):
            return xi * yi + yi + bi * (xi + yi + 1)

        polynomials = []
        for n in range(nsubtractions):  # z = (x - y) % 2^word_size
            if n == 0:
                x = input_vars[:word_size]
            else:
                x = aux_outputs_vars[n - 1]

            if n == nsubtractions - 1:
                z = output_vars
            else:
                z = aux_outputs_vars[n]

            y = input_vars[(n + 1) * word_size : (n + 2) * word_size]
            b = borrows_vars[n]

            polynomials += [b[0] + 0]
            polynomials += [x[0] + y[0] + z[0] + b[0]]

            for i in range(1, word_size):
                polynomials += [b[i] + borrow_polynomial(x[i - 1], y[i - 1], b[i - 1])]
                polynomials += [x[i] + y[i] + z[i] + b[i]]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for Modular Subtraction in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        .. WARNING::

            This method heavily relies on the fact that modular subtraction is always performed using two operands.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modsub_component import ModSub
            sage: modsub_component = ModSub(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
            sage: modsub_component.cms_constraints()[:1]
            (['temp_carry_input2_0', 'temp_input_input2_0', 'temp_input_input2_1', 'carry_modsub_0_0_0', 'modsub_0_0_0', 'modsub_0_0_1'],)
        """
        return self.sat_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for Modular Addition component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modsub_component import ModSub
            sage: modsub_component = ModSub(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
            sage: modsub_component.cp_constraints()[:1]
            (['array[0..1] of var 0..1: constant_modsub_0_0= array1d(0..1,[0, 1]);', 'array[0..1] of var 0..1: modsub_0_0;', 'array[0..1] of var 0..1:pre_modsub_0_0_0;', 'array[0..1] of var 0..1:pre_modsub_0_0_1;', 'array[0..1] of var 0..1:pre_minus_pre_modsub_0_0_1;', 'array[0..1] of var 0..1:minus_pre_modsub_0_0_1;'],)
        """
        output_size = self.output_bit_size
        output_id_link = self.id
        cp_declarations = []
        cp_constraints = []
        num_add = self.description[1]
        all_inputs = []
        for i, input_id_link in enumerate(self.input_id_links):
            for position in self.input_bit_positions[i]:
                all_inputs.append(f"{input_id_link}[{position}]")
        total_input_len = len(all_inputs)
        input_len = total_input_len // num_add
        new_declaration = (
            f"array[0..{output_size - 1}] of var 0..1: constant_{output_id_link}= array1d(0..{output_size - 1},["
        )
        for i in range(output_size - 1):
            new_declaration = new_declaration + "0, "
        new_declaration = new_declaration + "1]);"
        cp_declarations.append(new_declaration)
        cp_declarations.append(f"array[0..{output_size - 1}] of var 0..1: {output_id_link};")
        for i in range(num_add):
            cp_declarations.append(f"array[0..{input_len - 1}] of var 0..1:pre_{output_id_link}_{i};")
            for j in range(input_len):
                cp_constraints.append(f"constraint pre_{output_id_link}_{i}[{j}]={all_inputs[i * input_len + j]};")
        for i in range(num_add - 2):
            cp_declarations.append(f"array[0..{output_size - 1}] of var 0..1:temp_{output_id_link}_{i};")
        if num_add == 2:
            cp_twoterms(
                f"pre_{output_id_link}_0",
                f"pre_{output_id_link}_1",
                str(output_id_link),
                str(output_id_link),
                output_size,
                cp_constraints,
                cp_declarations,
            )
        elif num_add > 2:
            cp_twoterms(
                f"pre_{output_id_link}_0",
                f"pre_{output_id_link}_1",
                f"temp_{output_id_link}_0",
                str(output_id_link),
                output_size,
                cp_constraints,
                cp_declarations,
            )
            for i in range(1, num_add - 2):
                cp_twoterms(
                    f"pre_{output_id_link}_{i + 1}",
                    f"temp_{output_id_link}_{i - 1}",
                    f"temp_{output_id_link}_{i}",
                    str(output_id_link),
                    output_size,
                    cp_constraints,
                    cp_declarations,
                )
                cp_twoterms(
                    f"pre_{output_id_link}_{num_add - 1}",
                    f"temp_{output_id_link}_{num_add - 3}",
                    str(output_id_link),
                    str(output_id_link),
                    output_size,
                    cp_constraints,
                    cp_declarations,
                )

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [
            f"  {self.id} = bit_vector_MODSUB([{','.join(params)} ], {self.description[1]}, {self.output_bit_size})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_MODSUB({params})"]

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing MODULAR SUBTRACTION for SAT CIPHER model

        The list of contraints models the two's complement addtion.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        .. WARNING::

            This method heavily relies on the fact that modular subtraction is always performed using two operands.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modsub_component import ModSub
            sage: modsub_component = ModSub(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
            sage: modsub_component.sat_constraints()[:1]
            (['temp_carry_input2_0', 'temp_input_input2_0', 'temp_input_input2_1', 'carry_modsub_0_0_0', 'modsub_0_0_0', 'modsub_0_0_1'],)
        """
        output_bit_ids, temp_carry_bit_ids, temp_input_bit_ids, carry_bit_ids, lhs_input_bit_ids, rhs_input_bit_ids = (
            sat_generate_ids_for_modsub(self)
        )
        constraints = []
        # carries complement 2
        for temp_carry_bit_id, rhs_input_bit_id, prev_temp_carry_bit_id in zip(
            temp_carry_bit_ids[:-1], rhs_input_bit_ids[1:-1], temp_carry_bit_ids[1:]
        ):
            constraints.extend(sat_utils.cnf_carry_comp2(temp_carry_bit_id, rhs_input_bit_id, prev_temp_carry_bit_id))
        constraints.extend(sat_utils.cnf_inequality(temp_carry_bit_ids[-1], rhs_input_bit_ids[-1]))
        # results complement 2
        for temp_input_bit_id, rhs_input_bit_id, temp_carry_bit_id in zip(
            temp_input_bit_ids[:-1], rhs_input_bit_ids[:-1], temp_carry_bit_ids
        ):
            constraints.extend(sat_utils.cnf_result_comp2(temp_input_bit_id, rhs_input_bit_id, temp_carry_bit_id))
        constraints.extend(sat_utils.cnf_equivalent([temp_input_bit_ids[-1], rhs_input_bit_ids[-1]]))
        # carries
        for carry_bit_id, lhs_input_bit_id, temp_input_bit_id, prev_carry_bit_id in zip(
            carry_bit_ids[:-1], lhs_input_bit_ids[1:-1], temp_input_bit_ids[1:-1], carry_bit_ids[1:]
        ):
            constraints.extend(
                sat_utils.cnf_carry(carry_bit_id, lhs_input_bit_id, temp_input_bit_id, prev_carry_bit_id)
            )
        constraints.extend(sat_utils.cnf_and(carry_bit_ids[-1], (lhs_input_bit_ids[-1], temp_input_bit_ids[-1])))
        # results
        for output_bit_id, lhs_input_bit_id, temp_input_bit_id, carry_bit_id in zip(
            output_bit_ids[:-1], lhs_input_bit_ids[:-1], temp_input_bit_ids[:-1], carry_bit_ids
        ):
            constraints.extend(sat_utils.cnf_xor(output_bit_id, [lhs_input_bit_id, temp_input_bit_id, carry_bit_id]))
        constraints.extend(sat_utils.cnf_xor(output_bit_ids[-1], [lhs_input_bit_ids[-1], temp_input_bit_ids[-1]]))

        return temp_carry_bit_ids + temp_input_bit_ids + carry_bit_ids + output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing MODULAR SUBTRACTION for SMT CIPHER model

        The list of contraints models the two's complement addtion.

        .. WARNING::

            This method heavily relies on the fact that modular subtraction is always performed using two operands.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modsub_component import ModSub
            sage: modsub_component = ModSub(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
            sage: modsub_component.smt_constraints()[:1]
            (['temp_carry_input2_0', 'temp_input_input2_0', 'temp_input_input2_1', 'carry_modsub_0_0_0', 'modsub_0_0_0', 'modsub_0_0_1'],)
        """
        output_bit_ids, temp_carry_bit_ids, temp_input_bit_ids, carry_bit_ids, lhs_input_bit_ids, rhs_input_bit_ids = (
            sat_generate_ids_for_modsub(self)
        )
        constraints = []

        # carries complement 2
        for temp_carry_bit_id, rhs_input_bit_id, prev_temp_carry_bit_id in zip(
            temp_carry_bit_ids[:-1], rhs_input_bit_ids[1:-1], temp_carry_bit_ids[1:]
        ):
            operation = smt_utils.smt_and((smt_utils.smt_not(rhs_input_bit_id), prev_temp_carry_bit_id))
            equation = smt_utils.smt_equivalent((temp_carry_bit_id, operation))
            constraints.append(smt_utils.smt_assert(equation))
        distinction = smt_utils.smt_distinct(temp_carry_bit_ids[-1], rhs_input_bit_ids[-1])
        constraints.append(smt_utils.smt_assert(distinction))

        # results complement 2
        for temp_input_bit_id, rhs_input_bit_id, temp_carry_bit_id in zip(
            temp_input_bit_ids[:-1], rhs_input_bit_ids[:-1], temp_carry_bit_ids
        ):
            operation = smt_utils.smt_xor((smt_utils.smt_not(rhs_input_bit_id), temp_carry_bit_id))
            equation = smt_utils.smt_equivalent((temp_input_bit_id, operation))
            constraints.append(smt_utils.smt_assert(equation))
        equation = smt_utils.smt_equivalent((temp_input_bit_ids[-1], rhs_input_bit_ids[-1]))
        constraints.append(smt_utils.smt_assert(equation))

        # carries
        for carry_bit_id, lhs_input_bit_id, temp_input_bit_id, prev_carry_bit_id in zip(
            carry_bit_ids[:-1], lhs_input_bit_ids[1:-1], temp_input_bit_ids[1:-1], carry_bit_ids[1:]
        ):
            operation = smt_utils.smt_carry(lhs_input_bit_id, temp_input_bit_id, prev_carry_bit_id)
            equation = smt_utils.smt_equivalent((carry_bit_id, operation))
            constraints.append(smt_utils.smt_assert(equation))
        operation = smt_utils.smt_and((lhs_input_bit_ids[-1], temp_input_bit_ids[-1]))
        equation = smt_utils.smt_equivalent((carry_bit_ids[-1], operation))
        constraints.append(smt_utils.smt_assert(equation))

        # results
        for output_bit_id, lhs_input_bit_id, temp_input_bit_id, carry_bit_id in zip(
            output_bit_ids[:-1], lhs_input_bit_ids[:-1], temp_input_bit_ids[:-1], carry_bit_ids
        ):
            operation = smt_utils.smt_xor((lhs_input_bit_id, temp_input_bit_id, carry_bit_id))
            equation = smt_utils.smt_equivalent((output_bit_id, operation))
            constraints.append(smt_utils.smt_assert(equation))
        operation = smt_utils.smt_xor((lhs_input_bit_ids[-1], temp_input_bit_ids[-1]))
        equation = smt_utils.smt_equivalent((output_bit_ids[-1], operation))
        constraints.append(smt_utils.smt_assert(equation))

        return temp_carry_bit_ids + temp_input_bit_ids + carry_bit_ids + output_bit_ids, constraints

    def smt_xor_quasidifferential_propagation_constraints(
        self,
        model,
    ):
        """
        Return SMT constraints for MODSUB quasidifferential propagation.

        Modular subtraction reduces EXACTLY to modular addition with
        permuted roles: z = x - y is equivalent to x = z + y, so a
        MODSUB transition with input differences (A, B), output
        difference C, input masks (U, V) and output mask W has the
        same QDT coefficient as the MODADD transition with input
        differences (C, B), output difference A, input masks (W, V)
        and output mask U:

            D_MODSUB(A,B,C,U,V,W) == D_MODADD(C,B,A,W,V,U)

        i.e. simply swap A <-> C and U <-> W.

        This was verified by EXHAUSTIVE brute force of Equation (4)
        applied directly to modular subtraction and to modular
        addition, over all 3-bit (A,B,C,U,V,W) combinations: 6728
        valid transitions compared, 0 mismatches (and 255416
        combinations where both coefficients vanish).

        The constraints below are therefore ModAdd's own (Theorem 5.2
        of Beyne & Rijmen), with that permutation applied. Note that
        the two symmetric quantities -- A xor B xor C and U xor V xor W
        -- are unchanged by the swap, so only the primed variables
        a', b', u', v' differ from ModAdd's.

        Only 2 operands are supported, matching both Theorem 5.2 and
        this class's own SAT/SMT methods (which likewise assume two
        operands). This raises NotImplementedError rather than
        guessing; build_xor_quasidifferential_trail_model catches that
        and skips the component with a clear message.

        INPUT:

        - ``model`` -- **model object**; a model instance
        """

        num_operands = self.description[1]

        if num_operands != 2:
            raise NotImplementedError(
                f"{self.id}: quasidifferential propagation for MODSUB is "
                f"only implemented for 2 operands (Theorem 5.2 of "
                f"Beyne & Rijmen, via the reduction to MODADD); "
                f"got {num_operands}."
            )

        word_size = self.output_bit_size

        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()

        qdt_input_bit_ids = [f"qdt_{bit_id}" for bit_id in input_bit_ids]
        qdt_output_bit_ids = [f"qdt_{bit_id}" for bit_id in output_bit_ids]

        # MODSUB's own variables.
        A_ids = input_bit_ids[:word_size]
        B_ids = input_bit_ids[word_size:]
        C_ids = output_bit_ids

        U_ids = qdt_input_bit_ids[:word_size]
        V_ids = qdt_input_bit_ids[word_size:]
        W_ids = qdt_output_bit_ids

        # Apply the verified permutation to obtain MODADD's roles:
        # (a, b, c, u, v, w) = (C, B, A, W, V, U).
        a_ids, b_ids, c_ids = C_ids, B_ids, A_ids
        u_ids, v_ids, w_ids = W_ids, V_ids, U_ids

        constraints = []
        variables = list(output_bit_ids) + list(qdt_output_bit_ids)

        def new_named_formula(name_prefix, index, formula):
            variable_name = f"{name_prefix}_{self.id}_{index}"
            equation = smt_utils.smt_equivalent([variable_name, formula])
            constraints.append(smt_utils.smt_assert(equation))
            variables.append(variable_name)
            return variable_name

        # a' = b xor c ; b' = a xor c ; c' = M+(a xor b xor c)

        a_prime_ids = []
        b_prime_ids = []
        abc_xor_ids = []

        for i in range(word_size):
            a_prime_ids.append(new_named_formula("modsub_aprime", i, smt_utils.smt_xor([b_ids[i], c_ids[i]])))
            b_prime_ids.append(new_named_formula("modsub_bprime", i, smt_utils.smt_xor([a_ids[i], c_ids[i]])))
            abc_xor_ids.append(
                new_named_formula(
                    "modsub_abcxor",
                    i,
                    smt_utils.smt_xor([a_ids[i], b_ids[i], c_ids[i]]),
                )
            )

        c_prime_ids = ["false"] * word_size

        for q in range(1, word_size):
            c_prime_ids[q] = new_named_formula(
                "modsub_cprime",
                q,
                smt_utils.smt_xor([abc_xor_ids[q], abc_xor_ids[q - 1]]),
            )

        # u' = u xor w ; v' = v xor w ; w' = M^T(u xor v xor w)

        u_prime_ids = []
        v_prime_ids = []
        uvw_xor_ids = []

        for i in range(word_size):
            u_prime_ids.append(new_named_formula("modsub_uprime", i, smt_utils.smt_xor([u_ids[i], w_ids[i]])))
            v_prime_ids.append(new_named_formula("modsub_vprime", i, smt_utils.smt_xor([v_ids[i], w_ids[i]])))
            uvw_xor_ids.append(
                new_named_formula(
                    "modsub_uvwxor",
                    i,
                    smt_utils.smt_xor([u_ids[i], v_ids[i], w_ids[i]]),
                )
            )

        w_prime_ids = ["false"] * word_size
        prefix_xor = "false"

        for q in range(1, word_size):
            prefix_xor = new_named_formula(
                "modsub_wprime",
                q,
                smt_utils.smt_xor([prefix_xor, uvw_xor_ids[q - 1]]),
            )
            w_prime_ids[q] = prefix_xor

        # DIFFERENTIAL VALIDITY (Lipmaa-Moriai).
        #
        # Theorem 5.2's own conditions constrain the MASK side assuming
        # the differential (a, b) -> c is already valid: common.py can
        # omit this check because there a, b, c are CONSTANTS taken
        # from a known-good characteristic. Here they are variables, so
        # the classic modular-addition differential validity must be
        # asserted explicitly, otherwise the solver returns "trails"
        # whose true correlation is zero.
        #
        #   eq(a<<1, b<<1, c<<1) & (a xor b xor c xor (b<<1)) == 0
        #
        # In claasp's MSB-first indexing (index 0 = MSB), (x<<1)_i is
        # x_{i+1}, and 0 at the last index.

        for i in range(word_size):
            if i == word_size - 1:
                # LSB: eq is trivially true (all shifted-in bits are 0),
                # so the condition reduces to a xor b xor c == 0.
                constraints.append(
                    smt_utils.smt_assert(smt_utils.smt_not(smt_utils.smt_xor([a_ids[i], b_ids[i], c_ids[i]])))
                )
            else:
                bits_equal = smt_utils.smt_and(
                    [
                        smt_utils.smt_equivalent([a_ids[i + 1], b_ids[i + 1]]),
                        smt_utils.smt_equivalent([a_ids[i + 1], c_ids[i + 1]]),
                    ]
                )
                must_vanish = smt_utils.smt_xor([a_ids[i], b_ids[i], c_ids[i], b_ids[i + 1]])
                constraints.append(
                    smt_utils.smt_assert(smt_utils.smt_implies(bits_equal, smt_utils.smt_not(must_vanish)))
                )

        weight_bit_ids = []

        for i in range(word_size):
            a_p, b_p, c_p = a_prime_ids[i], b_prime_ids[i], c_prime_ids[i]
            u_p, v_p, w_p = u_prime_ids[i], v_prime_ids[i], w_prime_ids[i]

            validity_1 = smt_utils.smt_implies(
                smt_utils.smt_or([u_p, v_p]),
                smt_utils.smt_or([a_p, b_p, w_p]),
            )
            constraints.append(smt_utils.smt_assert(validity_1))

            validity_2 = smt_utils.smt_equivalent(
                [
                    smt_utils.smt_xor(
                        [
                            smt_utils.smt_and([a_p, u_p]),
                            smt_utils.smt_and([b_p, v_p]),
                        ]
                    ),
                    smt_utils.smt_and([c_p, w_p]),
                ]
            )
            constraints.append(smt_utils.smt_assert(validity_2))

            weight_bit_id = f"hw_qdt_{self.id}_{i}"
            weight_bit_ids.append(weight_bit_id)

            if i == 0:
                top_bit_validity = smt_utils.smt_or(
                    [
                        smt_utils.smt_and([smt_utils.smt_not(a_p), smt_utils.smt_not(b_p)]),
                        smt_utils.smt_equivalent(
                            [
                                smt_utils.smt_and([a_p, u_p]),
                                smt_utils.smt_xor([u_p, v_p]),
                            ]
                        ),
                    ]
                )
                constraints.append(smt_utils.smt_assert(top_bit_validity))

                weight_definition = smt_utils.smt_equivalent(
                    [
                        weight_bit_id,
                        "false",
                    ]
                )
            else:
                weight_definition = smt_utils.smt_equivalent(
                    [
                        weight_bit_id,
                        smt_utils.smt_or([a_p, b_p, w_p]),
                    ]
                )

            constraints.append(smt_utils.smt_assert(weight_definition))

        variables.extend(weight_bit_ids)

        return (
            variables,
            constraints,
        )
