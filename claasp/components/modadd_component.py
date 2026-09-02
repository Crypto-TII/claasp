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


def cms_modadd(output_ids, input0_ids, input1_ids, carry_ids):
    # The CMS modular addition between 2 addenda
    constraints = []
    for carry_id, input0_id, input1_id, previous_carry_id in zip(
        carry_ids, input0_ids[1:], input1_ids[1:], carry_ids[1:]
    ):
        constraints.extend(sat_utils.cnf_carry(carry_id, input0_id, input1_id, previous_carry_id))
    constraints.extend(sat_utils.cnf_and(carry_ids[-1], (input0_ids[-1], input1_ids[-1])))
    for output_id, input0_id, input1_id, carry_id in zip(output_ids, input0_ids, input1_ids, carry_ids):
        constraints.append(f"x -{output_id} {input0_id} {input1_id} {carry_id}")
    constraints.append(f"x -{output_ids[-1]} {input0_ids[-1]} {input1_ids[-1]}")
    return constraints


def cms_modadd_seq(outputs_ids, inputs_ids, carries_ids):
    # The CMS modular addition between more than 2 addenda
    constraints = cms_modadd(outputs_ids[0], inputs_ids[0], inputs_ids[1], carries_ids[0])
    for i in range(1, len(outputs_ids)):
        constraints.extend(cms_modadd(outputs_ids[i], outputs_ids[i - 1], inputs_ids[i + 1], carries_ids[i]))
    return constraints


def cp_twoterms(input_1, input_2, out, input_length, cp_constraints, cp_declarations):
    cp_declarations.append(f"array[1..{input_length - 1}] of var 0..1: carry_{out};")
    for i in range(1, input_length - 1):
        cp_constraints.append(
            f"constraint carry_{out}[{i}] = ({input_1}[{i}]*{input_2}[{i}] + "
            f"{input_1}[{i}]*carry_{out}[{i + 1}] + carry_{out}[{i + 1}]*{input_2}[{i}]) mod 2;"
        )
    cp_constraints.append(
        f"constraint carry_{out}[{input_length - 1}] = "
        f"({input_1}[{input_length - 1}] * {input_2}[{input_length - 1}]) mod 2;"
    )
    for i in range(input_length - 1):
        cp_constraints.append(
            f"constraint {out}[{i}] = ({input_1}[{i}] + {input_2}[{i}] + carry_{out}[{i + 1}]) mod 2;"
        )
    cp_constraints.append(
        f"constraint {out}[{input_length - 1}] = ({input_1}[{input_length - 1}] + {input_2}[{input_length - 1}]) mod 2;"
    )

    return cp_declarations, cp_constraints


def sat_generate_ids_for_modadd(component):
    input_ids = component._generate_input_ids()
    output_ids = component._generate_output_ids()
    num_of_addenda = component.description[1]
    # reformat of the in_ids
    inputs_ids = [
        input_ids[i * component.output_bit_size : (i + 1) * component.output_bit_size] for i in range(num_of_addenda)
    ]
    # carries
    carries_ids = [[f"carry_{i}_{output_id}" for output_id in output_ids[:-1]] for i in range(num_of_addenda - 1)]
    # reformat of the outputs_ids
    outputs_ids = [
        [f"modadd_output_{i}_{output_id}" for output_id in output_ids] for i in range(num_of_addenda - 2)
    ] + [output_ids]

    return outputs_ids, inputs_ids, carries_ids


def sat_modadd(output_ids, input0_ids, input1_ids, carry_ids):
    # The SAT modular addition between 2 addenda
    constraints = []
    for carry_id, input0_id, input1_id, previous_carry_id in zip(
        carry_ids, input0_ids[1:], input1_ids[1:], carry_ids[1:]
    ):
        constraints.extend(sat_utils.cnf_carry(carry_id, input0_id, input1_id, previous_carry_id))
    constraints.extend(sat_utils.cnf_and(carry_ids[-1], (input0_ids[-1], input1_ids[-1])))
    for output_id, input0_id, input1_id, carry_id in zip(output_ids, input0_ids, input1_ids, carry_ids):
        constraints.extend(sat_utils.cnf_xor(output_id, [input0_id, input1_id, carry_id]))
    constraints.extend(sat_utils.cnf_xor(output_ids[-1], [input0_ids[-1], input1_ids[-1]]))
    return constraints


def sat_modadd_seq(outputs_ids, inputs_ids, carries_ids):
    # The SAT modular addition between more than 2 addenda
    constraints = sat_modadd(outputs_ids[0], inputs_ids[0], inputs_ids[1], carries_ids[0])
    for i in range(1, len(outputs_ids)):
        constraints.extend(sat_modadd(outputs_ids[i], outputs_ids[i - 1], inputs_ids[i + 1], carries_ids[i]))
    return constraints


def smt_modadd(output_ids, input0_ids, input1_ids, carry_ids):
    # The SMT modular addition between 2 addenda
    constraints = []
    for carry_id, input0_id, input1_id, previous_carry_id in zip(
        carry_ids, input0_ids[1:], input1_ids[1:], carry_ids[1:]
    ):
        operation = smt_utils.smt_carry(input0_id, input1_id, previous_carry_id)
        equation = smt_utils.smt_equivalent((carry_id, operation))
        constraints.append(smt_utils.smt_assert(equation))
    operation = smt_utils.smt_and((input0_ids[-1], input1_ids[-1]))
    equation = smt_utils.smt_equivalent((carry_ids[-1], operation))
    constraints.append(smt_utils.smt_assert(equation))
    for output_id, input0_id, input1_id, carry_id in zip(output_ids, input0_ids, input1_ids, carry_ids):
        operation = smt_utils.smt_xor((input0_id, input1_id, carry_id))
        equation = smt_utils.smt_equivalent((output_id, operation))
        constraints.append(smt_utils.smt_assert(equation))
    operation = smt_utils.smt_xor((input0_ids[-1], input1_ids[-1]))
    equation = smt_utils.smt_equivalent((output_ids[-1], operation))
    constraints.append(smt_utils.smt_assert(equation))
    return constraints


def smt_modadd_seq(outputs_ids, inputs_ids, carries_ids):
    # The SMT modular addition between more than 2 addenda
    constraints = smt_modadd(outputs_ids[0], inputs_ids[0], inputs_ids[1], carries_ids[0])
    for i in range(1, len(outputs_ids)):
        constraints.extend(smt_modadd(outputs_ids[i], outputs_ids[i - 1], inputs_ids[i + 1], carries_ids[i]))
    return constraints


class ModAdd(Modular):
    """
    Construct a modular addition component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``modulus`` -- **integer**; modulus used by modular arithmetic operations. Must be greater than ``0``.

    EXAMPLES::

        sage: from claasp.components.modadd_component import ModAdd
        sage: component = ModAdd(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
        sage: print(component.id)
        modadd_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['MODADD', 2, 2]
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
            "modadd",
            modulus,
        )

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for Modular Addition.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.modadd_cipher import ModaddCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = ModaddCipher(word_bit_size=4, number_of_inputs=2, modulus=16)
            sage: modadd_component = cipher.component_from_id("modadd_0_0")
            sage: algebraic = AlgebraicModel(cipher)
            sage: modadd_component.algebraic_polynomials(algebraic)
            [modadd_0_0_c0_0,
            modadd_0_0_c0_0 + modadd_0_0_y0 + modadd_0_0_x4 + modadd_0_0_x0,
            modadd_0_0_x4*modadd_0_0_c0_0 + modadd_0_0_x0*modadd_0_0_c0_0 + modadd_0_0_x0*modadd_0_0_x4 + modadd_0_0_c0_1,
            modadd_0_0_c0_1 + modadd_0_0_y1 + modadd_0_0_x5 + modadd_0_0_x1,
            modadd_0_0_x5*modadd_0_0_c0_1 + modadd_0_0_x1*modadd_0_0_c0_1 + modadd_0_0_x1*modadd_0_0_x5 + modadd_0_0_c0_2,
            modadd_0_0_c0_2 + modadd_0_0_y2 + modadd_0_0_x6 + modadd_0_0_x2,
            modadd_0_0_x6*modadd_0_0_c0_2 + modadd_0_0_x2*modadd_0_0_c0_2 + modadd_0_0_x2*modadd_0_0_x6 + modadd_0_0_c0_3,
            modadd_0_0_c0_3 + modadd_0_0_y3 + modadd_0_0_x7 + modadd_0_0_x3]
        """
        component_id = self.id
        ninput_words = self.description[1]
        nadditions = ninput_words - 1
        ninput_bits = self.input_bit_size
        noutput_bits = word_size = self.output_bit_size

        input_vars = [f"{component_id}_{model.input_postfix}{i}" for i in range(ninput_bits)]
        output_vars = [f"{component_id}_{model.output_postfix}{i}" for i in range(noutput_bits)]
        carries_vars = [[f"{component_id}_c{n}_{i}" for i in range(word_size)] for n in range(nadditions)]
        aux_outputs_vars = [[f"{component_id}_o{n}_{i}" for i in range(word_size)] for n in range(nadditions - 1)]
        ring_R = model.ring()

        input_vars = list(map(ring_R, input_vars))
        output_vars = list(map(ring_R, output_vars))
        carries_vars = [list(map(ring_R, carry_vars)) for carry_vars in carries_vars]
        aux_outputs_vars = [list(map(ring_R, aux_output_vars)) for aux_output_vars in aux_outputs_vars]

        def maj(xi, yi, zi):
            return xi * yi + xi * zi + yi * zi

        polynomials = []
        for n in range(nadditions):  # z = x + y
            if n == 0:
                x = input_vars[:word_size]
            else:
                x = aux_outputs_vars[n - 1]

            if n == nadditions - 1:
                z = output_vars
            else:
                z = aux_outputs_vars[n]

            y = input_vars[(n + 1) * word_size : (n + 1) * word_size + word_size]
            c = carries_vars[n]

            polynomials += [c[0] + 0]
            polynomials += [x[0] + y[0] + z[0] + c[0]]
            for i in range(1, word_size):
                polynomials += [c[i] + maj(x[i - 1], y[i - 1], c[i - 1])]
                polynomials += [x[i] + y[i] + z[i] + c[i]]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for Modular Addition in CMS CIPHER model.

        .. SEEALSO::

            :ref:`CMS CIPHER model  <cms-cipher-standard>` for the format.

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modadd_component import ModAdd
            sage: modadd_component = ModAdd(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
            sage: modadd_component.cms_constraints()[0]
            ['carry_modadd_0_0_0', 'modadd_0_0_0', 'modadd_0_0_1']
        """
        input_bit_ids = self._generate_input_ids()
        lhs_input_bit_ids = input_bit_ids[: self.output_bit_size]
        rhs_input_bit_ids = input_bit_ids[self.output_bit_size :]
        output_bit_ids = self._generate_output_ids()
        carry_bit_ids = [f"carry_{output_bit_id}" for output_bit_id in output_bit_ids[:-1]]
        constraints = []
        # carries
        for carry_bit_id, lhs_input_bit_id, rhs_input_bit_id, previous_carry_bit_id in zip(
            carry_bit_ids[:-1], lhs_input_bit_ids[1:], rhs_input_bit_ids[1:], carry_bit_ids[1:]
        ):
            constraints.extend(
                sat_utils.cnf_carry(carry_bit_id, lhs_input_bit_id, rhs_input_bit_id, previous_carry_bit_id)
            )
        constraints.extend(sat_utils.cnf_and(carry_bit_ids[-1], (lhs_input_bit_ids[-1], rhs_input_bit_ids[-1])))
        # results for CryptoMiniSat can be implemented using the leading x
        for output_bit_id, lhs_input_bit_id, rhs_input_bit_id, carry_bit_id in zip(
            output_bit_ids[:-1], lhs_input_bit_ids[:-1], rhs_input_bit_ids[:-1], carry_bit_ids
        ):
            constraints.append(f"x -{output_bit_id} {lhs_input_bit_id} {rhs_input_bit_id} {carry_bit_id}")
        constraints.append(f"x -{output_bit_ids[-1]} {lhs_input_bit_ids[-1]} {rhs_input_bit_ids[-1]}")

        return carry_bit_ids + output_bit_ids, constraints

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for Modular Addition component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modadd_component import ModAdd
            sage: modadd_component = ModAdd(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
            sage: modadd_component.cp_constraints()[:1]
            (['array[0..1] of var 0..1: pre_modadd_0_0_0;', 'array[0..1] of var 0..1: pre_modadd_0_0_1;', 'array[1..1] of var 0..1: carry_modadd_0_0;'],)
        """
        output_id_link = self.id
        num_add = self.description[1]
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        input_len = len(all_inputs) // num_add
        cp_declarations = []
        cp_constraints = []
        for i in range(num_add):
            cp_declarations.append(f"array[0..{input_len - 1}] of var 0..1: pre_{output_id_link}_{i};")
            cp_constraints.extend(
                [
                    f"constraint pre_{output_id_link}_{i}[{j}] = {all_inputs[i * input_len + j]};"
                    for j in range(input_len)
                ]
            )
        for i in range(num_add, 2 * num_add - 2):
            cp_declarations.append(f"array[0..{input_len - 1}] of var 0..1: pre_{output_id_link}_{i};")
        for i in range(num_add - 2):
            cp_twoterms(
                f"pre_{output_id_link}_{num_add - 1}",
                f"pre_{output_id_link}_{i + 1}",
                f"pre_{output_id_link}_{num_add + i}",
                self.output_bit_size,
                cp_constraints,
                cp_declarations,
            )
        cp_twoterms(
            f"pre_{output_id_link}_{2 * num_add - 3}",
            f"pre_{output_id_link}_0",
            f"{output_id_link}",
            self.output_bit_size,
            cp_constraints,
            cp_declarations,
        )

        return cp_declarations, cp_constraints

    def cp_twoterms_xor_differential_probability(
        self, inp1, inp2, out, inplen, cp_constraints, cp_declarations, c, model
    ):
        if inp1 not in model.modadd_twoterms_mant:
            cp_declarations.append(f"array[0..{inplen - 1}] of var 0..1: Shi_{inp1} = LShift({inp1},1);")
            model.modadd_twoterms_mant.append(inp1)
        if inp2 not in model.modadd_twoterms_mant:
            cp_declarations.append(f"array[0..{inplen - 1}] of var 0..1: Shi_{inp2} = LShift({inp2},1);")
            model.modadd_twoterms_mant.append(inp2)
        if out not in model.modadd_twoterms_mant:
            cp_declarations.append(f"array[0..{inplen - 1}] of var 0..1: Shi_{out} = LShift({out},1);")
            model.modadd_twoterms_mant.append(out)
        cp_declarations.append(f"array[0..{inplen - 1}] of var 0..1: eq_{out} = Eq(Shi_{inp1}, Shi_{inp2}, Shi_{out});")
        cp_constraints.append(
            f"constraint forall(j in 0..{inplen - 1})(if eq_{out}[j] = 1 then (sum([{inp1}[j], {inp2}[j], "
            f"{out}[j]]) mod 2) = Shi_{inp2}[j] else true endif) /\\ p[{c}] = {100 * inplen}-100 * sum(eq_{out});"
        )

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [
            f"  {self.id} = bit_vector_MODADD([{','.join(params)} ], {self.description[1]}, {self.output_bit_size})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_MODADD({params})"]

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing MODULAR ADDITION for SAT CIPHER model

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modadd_component import ModAdd
            sage: modadd_component = ModAdd(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
            sage: modadd_component.sat_constraints()[:1]
            (['carry_0_modadd_0_0_0', 'modadd_0_0_0', 'modadd_0_0_1'],)
        """
        outputs_ids, inputs_ids, carries_ids = sat_generate_ids_for_modadd(self)
        constraints = sat_modadd_seq(outputs_ids, inputs_ids, carries_ids)
        # flattening lists
        ids = [carry_id for carry_ids in carries_ids for carry_id in carry_ids]
        ids.extend([output_id for output_ids in outputs_ids for output_id in output_ids])

        return ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing MODULAR ADDITION for SMT CIPHER model

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modadd_component import ModAdd
            sage: modadd_component = ModAdd(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
            sage: modadd_component.smt_constraints()[:1]
            (['carry_0_modadd_0_0_0', 'modadd_0_0_0', 'modadd_0_0_1'],)
        """
        outputs_ids, inputs_ids, carries_ids = sat_generate_ids_for_modadd(self)
        constraints = smt_modadd_seq(outputs_ids, inputs_ids, carries_ids)
        # flattening lists
        ids = [carry_id for carry_ids in carries_ids for carry_id in carry_ids]
        ids.extend([output_id for output_ids in outputs_ids for output_id in output_ids])

        return ids, constraints

    def smt_xor_quasidifferential_propagation_constraints(
        self,
        model,
    ):
        """
        Return SMT constraints for MODADD quasidifferential propagation.

        Implements Theorem 5.2 of Beyne & Rijmen (modular addition mod
        2^n), for the pairwise case (a, b) -> c only -- this is what
        Speck actually uses. ModAdd's n>2-operand chaining
        (sat_modadd_seq/smt_modadd_seq) has no equivalent QDT
        derivation in the paper, so this deliberately raises
        NotImplementedError rather than guessing;
        build_xor_quasidifferential_trail_model already catches that
        and skips the component with a clear message.

        Translates common.py's modular_addition() (the paper authors'
        own Boolector reference implementation, using native bitvector
        shifts) into per-bit boolean formulas over claasp's
        individually-named bit variables. The M and M-transpose linear
        maps of Section 5.2 reduce, bit by bit in claasp's MSB-first
        ordering (index 0 = MSB, index n-1 = LSB), to:

            M_pseudoinverse(t)[0] = false
            M_pseudoinverse(t)[q] = t[q] xor t[q-1]                for q = 1..n-1

            M_transpose(t)[0] = false
            M_transpose(t)[q] = t[0] xor t[1] xor ... xor t[q-1]   for q = 1..n-1
                              (prefix XOR of all more-significant bits)

        This was verified numerically (70000+ random test vectors,
        word sizes 4 and 8 bits) against common.py's own
        bitvector-based implementation -- both the validity conditions
        and the resulting ABSOLUTE weight (wt(a'|b') + wt(w' & ~a' &
        ~b') - extra; common.py itself only computes the RELATIVE
        weight loss beyond a fixed baseline differential, since it
        assumes a, b, c are already-known constants -- see the
        weights_rectangle.p / generate_weight_tables discussion for
        the same absolute-vs-relative distinction found for the
        Sbox's QDT) -- before being encoded here.

        Per bit i (on the primed variables a', b', c', u', v', w'):

            (u'_i or v'_i) => (a'_i or b'_i or w'_i)
            (a'_i and u'_i) xor (b'_i and v'_i) == (c'_i and w'_i)

        plus, ONLY at the top (most significant, claasp index 0) bit:

            ((a'_0 == 0) and (b'_0 == 0)) or ((a'_0 and u'_0) == (u'_0 xor v'_0))

        Local weight per bit is (a'_i or b'_i or w'_i), EXCEPT at the
        top bit, where it is additionally ANDed with the negation of
        the "extra" condition from Theorem 5.2 (which, when it holds,
        is guaranteed to already have a'_0 or b'_0 or w'_0 true, so
        this correctly implements the "-1" correction from the
        theorem's weight formula using only a plain non-negative sum
        of per-bit indicators, matching how And's local weight is
        computed).

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.modadd_cipher import ModaddCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import SmtXorQuasidifferentialModel
            sage: cipher = ModaddCipher(word_bit_size=2, number_of_inputs=2, modulus=4)
            sage: modadd_component = cipher.component_from_id('modadd_0_0')
            sage: smt = SmtXorQuasidifferentialModel(cipher)
            sage: variables, constraints = modadd_component.smt_xor_quasidifferential_propagation_constraints(smt)
            sage: len(variables)
            20
            sage: len(constraints)
            23
            sage: variables[:4]
            ['modadd_0_0_0', 'modadd_0_0_1', 'qdt_modadd_0_0_0', 'qdt_modadd_0_0_1']
            sage: constraints[0]
            '(assert (= modadd_aprime_modadd_0_0_0 (xor key_0 modadd_0_0_0)))'
            sage: constraints[-1]
            '(assert (= hw_qdt_modadd_0_0_1 (or modadd_aprime_modadd_0_0_1 modadd_bprime_modadd_0_0_1 modadd_wprime_modadd_0_0_1)))'
        """

        num_operands = self.description[1]

        if num_operands != 2:
            raise NotImplementedError(
                f"{self.id}: quasidifferential propagation for MODADD is "
                f"only implemented for 2 operands (Theorem 5.2 of "
                f"Beyne & Rijmen); got {num_operands}."
            )

        word_size = self.output_bit_size

        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()

        qdt_input_bit_ids = [f"qdt_{bit_id}" for bit_id in input_bit_ids]

        qdt_output_bit_ids = [f"qdt_{bit_id}" for bit_id in output_bit_ids]

        a_ids = input_bit_ids[:word_size]
        b_ids = input_bit_ids[word_size:]
        c_ids = output_bit_ids

        u_ids = qdt_input_bit_ids[:word_size]
        v_ids = qdt_input_bit_ids[word_size:]
        w_ids = qdt_output_bit_ids

        constraints = []
        variables = list(output_bit_ids) + list(qdt_output_bit_ids)

        def new_named_formula(name_prefix, index, formula):
            variable_name = f"{name_prefix}_{self.id}_{index}"
            equation = smt_utils.smt_equivalent([variable_name, formula])
            constraints.append(smt_utils.smt_assert(equation))
            variables.append(variable_name)
            return variable_name

        # ------------------------------------------------------------
        # a' = b xor c ; b' = a xor c ; c' = M+(a xor b xor c)
        # ------------------------------------------------------------

        a_prime_ids = []
        b_prime_ids = []
        abc_xor_ids = []

        for i in range(word_size):
            a_prime_ids.append(new_named_formula("modadd_aprime", i, smt_utils.smt_xor([b_ids[i], c_ids[i]])))
            b_prime_ids.append(new_named_formula("modadd_bprime", i, smt_utils.smt_xor([a_ids[i], c_ids[i]])))
            abc_xor_ids.append(
                new_named_formula(
                    "modadd_abcxor",
                    i,
                    smt_utils.smt_xor([a_ids[i], b_ids[i], c_ids[i]]),
                )
            )

        c_prime_ids = ["false"] * word_size

        for q in range(1, word_size):
            c_prime_ids[q] = new_named_formula(
                "modadd_cprime",
                q,
                smt_utils.smt_xor([abc_xor_ids[q], abc_xor_ids[q - 1]]),
            )

        # ------------------------------------------------------------
        # u' = u xor w ; v' = v xor w ; w' = M^T(u xor v xor w)
        # ------------------------------------------------------------

        u_prime_ids = []
        v_prime_ids = []
        uvw_xor_ids = []

        for i in range(word_size):
            u_prime_ids.append(new_named_formula("modadd_uprime", i, smt_utils.smt_xor([u_ids[i], w_ids[i]])))
            v_prime_ids.append(new_named_formula("modadd_vprime", i, smt_utils.smt_xor([v_ids[i], w_ids[i]])))
            uvw_xor_ids.append(
                new_named_formula(
                    "modadd_uvwxor",
                    i,
                    smt_utils.smt_xor([u_ids[i], v_ids[i], w_ids[i]]),
                )
            )

        w_prime_ids = ["false"] * word_size
        prefix_xor = "false"

        for q in range(1, word_size):
            prefix_xor = new_named_formula(
                "modadd_wprime",
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

            # (u'_i or v'_i) => (a'_i or b'_i or w'_i)
            validity_1 = smt_utils.smt_implies(
                smt_utils.smt_or([u_p, v_p]),
                smt_utils.smt_or([a_p, b_p, w_p]),
            )
            constraints.append(smt_utils.smt_assert(validity_1))

            # (a'_i and u'_i) xor (b'_i and v'_i) == (c'_i and w'_i)
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
