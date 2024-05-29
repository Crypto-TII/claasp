
# ****************************************************************************
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


from claasp.components.modular_component import Modular
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.sat.utils import utils as sat_utils


def cms_modadd(output_ids, input0_ids, input1_ids, carry_ids):
    # The CMS modular addition between 2 addenda
    constraints = []
    for carry_id, input0_id, input1_id, previous_carry_id in zip(carry_ids, input0_ids[1:],
                                                                 input1_ids[1:], carry_ids[1:]):
        constraints.extend(sat_utils.cnf_carry(carry_id, input0_id, input1_id, previous_carry_id))
    constraints.extend(sat_utils.cnf_and(carry_ids[-1], (input0_ids[-1], input1_ids[-1])))
    for output_id, input0_id, input1_id, carry_id in zip(output_ids, input0_ids, input1_ids, carry_ids):
        constraints.append(f'x -{output_id} {input0_id} {input1_id} {carry_id}')
    constraints.append(f'x -{output_ids[-1]} {input0_ids[-1]} {input1_ids[-1]}')
    return constraints


def cms_modadd_seq(outputs_ids, inputs_ids, carries_ids):
    # The CMS modular addition between more than 2 addenda
    constraints = cms_modadd(outputs_ids[0], inputs_ids[0], inputs_ids[1], carries_ids[0])
    for i in range(1, len(outputs_ids)):
        constraints.extend(cms_modadd(outputs_ids[i], outputs_ids[i - 1], inputs_ids[i + 1], carries_ids[i]))
    return constraints


def cp_twoterms(input_1, input_2, out, input_length, cp_constraints, cp_declarations):
    cp_declarations.append(f'array[1..{input_length - 1}] of var 0..1: carry_{out};')
    for i in range(1, input_length - 1):
        cp_constraints.append(
            f'constraint carry_{out}[{i}] = ({input_1}[{i}]*{input_2}[{i}] + '
            f'{input_1}[{i}]*carry_{out}[{i + 1}] + carry_{out}[{i + 1}]*{input_2}[{i}]) mod 2;')
    cp_constraints.append(f'constraint carry_{out}[{input_length - 1}] = '
                          f'({input_1}[{input_length - 1}] * {input_2}[{input_length - 1}]) mod 2;')
    for i in range(input_length - 1):
        cp_constraints.append(f'constraint {out}[{i}] = '
                              f'({input_1}[{i}] + {input_2}[{i}] + carry_{out}[{i + 1}]) mod 2;')
    cp_constraints.append(f'constraint {out}[{input_length - 1}] = '
                          f'({input_1}[{input_length - 1}] + {input_2}[{input_length - 1}]) mod 2;')

    return cp_declarations, cp_constraints


def sat_modadd(output_ids, input0_ids, input1_ids, carry_ids):
    # The SAT modular addition between 2 addenda
    constraints = []
    for carry_id, input0_id, input1_id, previous_carry_id in zip(carry_ids, input0_ids[1:], input1_ids[1:], carry_ids[1:]):
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
    for carry_id, input0_id, input1_id, previous_carry_id in zip(carry_ids, input0_ids[1:], input1_ids[1:], carry_ids[1:]):
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


class MODADD(Modular):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, modulus):
        super().__init__(current_round_number, current_round_number_of_components,
                         input_id_links, input_bit_positions, output_bit_size, 'modadd', modulus)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for Modular Addition.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=2)
            sage: modadd_component = fancy.get_component_from_id("modadd_1_9")
            sage: algebraic = AlgebraicModel(fancy)
            sage: modadd_component.algebraic_polynomials(algebraic)
            [modadd_1_9_c0_0,
             modadd_1_9_o0_0 + modadd_1_9_c0_0 + modadd_1_9_x6 + modadd_1_9_x0,
             ...
             modadd_1_9_o0_4*modadd_1_9_c1_4 + modadd_1_9_x16*modadd_1_9_c1_4 + modadd_1_9_x16*modadd_1_9_o0_4 + modadd_1_9_c1_5,
             modadd_1_9_c1_5 + modadd_1_9_o0_5 + modadd_1_9_y5 + modadd_1_9_x17]
        """
        component_id = self.id
        ninput_words = self.description[1]
        nadditions = ninput_words - 1
        ninput_bits = self.input_bit_size
        noutput_bits = word_size = self.output_bit_size

        input_vars = [component_id + "_" + model.input_postfix + str(i) for i in range(ninput_bits)]
        output_vars = [component_id + "_" + model.output_postfix + str(i) for i in range(noutput_bits)]
        carries_vars = \
            [[component_id + "_" + "c" + str(n) + "_" + str(i) for i in range(word_size)] for n in range(nadditions)]
        aux_outputs_vars = [[component_id + "_" + "o" + str(n) + "_" + str(i) for i in range(word_size)] for n in
                            range(nadditions - 1)]
        ring_R = model.ring()

        input_vars = list(map(ring_R, input_vars))
        output_vars = list(map(ring_R, output_vars))
        carries_vars = [list(map(ring_R, carry_vars)) for carry_vars in carries_vars]
        aux_outputs_vars = [list(map(ring_R, aux_output_vars)) for aux_output_vars in aux_outputs_vars]

        def maj(xi, yi, zi): return xi * yi + xi * zi + yi * zi
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

            y = input_vars[(n + 1) * word_size: (n + 1) * word_size + word_size]
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

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: modadd_component = speck.component_from(0,1)
            sage: modadd_component.cms_constraints()
            (['carry_modadd_0_1_0',
              'carry_modadd_0_1_1',
              'carry_modadd_0_1_2',
              ...
              'x -modadd_0_1_13 rot_0_0_13 plaintext_29 carry_modadd_0_1_13',
              'x -modadd_0_1_14 rot_0_0_14 plaintext_30 carry_modadd_0_1_14',
              'x -modadd_0_1_15 rot_0_0_15 plaintext_31'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        carry_bit_ids = [f'carry_{output_bit_ids[i]}' for i in range(output_bit_len - 1)]
        constraints = []
        # carries
        for i in range(output_bit_len - 2):
            constraints.extend(sat_utils.cnf_carry(carry_bit_ids[i],
                                                   input_bit_ids[i + 1],
                                                   input_bit_ids[output_bit_len + i + 1],
                                                   carry_bit_ids[i + 1]))
        constraints.extend(sat_utils.cnf_and(carry_bit_ids[output_bit_len - 2],
                                             (input_bit_ids[output_bit_len - 1],
                                              input_bit_ids[2 * output_bit_len - 1])))
        # results for CryptoMiniSat can be implemented using the leading x
        for i in range(output_bit_len - 1):
            constraints.append(f'x -{output_bit_ids[i]} '
                               f'{input_bit_ids[i]} '
                               f'{input_bit_ids[output_bit_len + i]} '
                               f'{carry_bit_ids[i]}')
        constraints.append(f'x -{output_bit_ids[output_bit_len - 1]} '
                           f'{input_bit_ids[output_bit_len - 1]} '
                           f'{input_bit_ids[2 * output_bit_len - 1]}')

        return carry_bit_ids + output_bit_ids, constraints

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for Modular Addition component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: modadd_component = speck.component_from(0, 1)
            sage: modadd_component.cp_constraints()
            (['array[0..15] of var 0..1: pre_modadd_0_1_0;',
              'array[0..15] of var 0..1: pre_modadd_0_1_1;',
              'array[1..15] of var 0..1: carry_modadd_0_1;'],
             ['constraint pre_modadd_0_1_0[0] = rot_0_0[0];',
              ...
              'constraint modadd_0_1[14] = (pre_modadd_0_1_1[14] + pre_modadd_0_1_0[14] + carry_modadd_0_1[15]) mod 2;',
              'constraint modadd_0_1[15] = (pre_modadd_0_1_1[15] + pre_modadd_0_1_0[15]) mod 2;'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        num_add = self.description[1]
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        input_len = len(all_inputs) // num_add
        cp_declarations = []
        cp_constraints = []
        for i in range(num_add):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..1: pre_{output_id_link}_{i};')
            cp_constraints.extend([f'constraint pre_{output_id_link}_{i}[{j}] = {all_inputs[i * input_len + j]};'
                                   for j in range(input_len)])
        for i in range(num_add, 2 * num_add - 2):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..1: pre_{output_id_link}_{i};')
        for i in range(num_add - 2):
            cp_twoterms(f'pre_{output_id_link}_{num_add - 1}', f'pre_{output_id_link}_{i + 1}',
                        f'pre_{output_id_link}_{num_add + i}', output_size,
                        cp_constraints, cp_declarations)
        cp_twoterms(f'pre_{output_id_link}_{2 * num_add - 3}', f'pre_{output_id_link}_0', f'{output_id_link}',
                    output_size, cp_constraints, cp_declarations)

        return cp_declarations, cp_constraints

    def cp_twoterms_xor_differential_probability(self, inp1, inp2, out, inplen, cp_constraints, cp_declarations, c, model):
        if inp1 not in model.modadd_twoterms_mant:
            cp_declarations.append(f'array[0..{inplen - 1}] of var 0..1: Shi_{inp1} = LShift({inp1},1);')
            model.modadd_twoterms_mant.append(inp1)
        if inp2 not in model.modadd_twoterms_mant:
            cp_declarations.append(f'array[0..{inplen - 1}] of var 0..1: Shi_{inp2} = LShift({inp2},1);')
            model.modadd_twoterms_mant.append(inp2)
        if out not in model.modadd_twoterms_mant:
            cp_declarations.append(f'array[0..{inplen - 1}] of var 0..1: Shi_{out} = LShift({out},1);')
            model.modadd_twoterms_mant.append(out)
        cp_declarations.append(f'array[0..{inplen - 1}] of var 0..1: eq_{out} = Eq(Shi_{inp1}, Shi_{inp2}, Shi_{out});')
        cp_constraints.append(
            f'constraint forall(j in 0..{inplen - 1})(if eq_{out}[j] = 1 then (sum([{inp1}[j], {inp2}[j], '
            f'{out}[j]]) mod 2) = Shi_{inp2}[j] else true endif) /\\ p[{c}] = {100 * inplen}-100 * sum(eq_{out});')

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = '
                f'bit_vector_MODADD([{",".join(params)} ], {self.description[1]}, {self.output_bit_size})']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_MODADD({params})']

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for Modular Addition in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: modadd_component = speck.component_from(0, 1)
            sage: modadd_component.sat_constraints()
            (['carry_modadd_0_1_0',
              'carry_modadd_0_1_1',
              'carry_modadd_0_1_2',
              ...
              'modadd_0_1_15 -rot_0_0_15 plaintext_31',
              'modadd_0_1_15 rot_0_0_15 -plaintext_31',
              '-modadd_0_1_15 -rot_0_0_15 -plaintext_31'])
        """
        _, input_ids = self._generate_input_ids()
        output_len, output_ids = self._generate_output_ids()
        num_of_addenda = self.description[1]
        # reformat of the in_ids
        inputs_ids = [input_ids[i * output_len: (i + 1) * output_len] for i in range(num_of_addenda)]
        # carries
        carries_ids = [[f'carry_{i}_{output_id}' for output_id in output_ids[:-1]]
                       for i in range(num_of_addenda - 1)]
        # reformat of the outputs_ids
        outputs_ids = [[f'modadd_output_{i}_{output_id}' for output_id in output_ids]
                       for i in range(num_of_addenda - 2)] + [output_ids]
        constraints = sat_modadd_seq(outputs_ids, inputs_ids, carries_ids)
        # flattening lists
        ids = [carry_id for carry_ids in carries_ids for carry_id in carry_ids]
        ids.extend([output_id for output_ids in outputs_ids for output_id in output_ids])
        return ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts for Modular Addition for SMT CIPHER model.

        .. WARNING::

            This method heavily relies on the fact that modular addition is always performed using two addenda.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: modadd_component = tea.component_from(0, 1)
            sage: modadd_component.smt_constraints()
            (['carry_0_modadd_0_1_0',
              'carry_0_modadd_0_1_1',
              ...
              'carry_0_modadd_0_1_29',
              'carry_0_modadd_0_1_30',
              'modadd_0_1_0',
              'modadd_0_1_1',
              ...
              'modadd_0_1_30',
              'modadd_0_1_31'],
             ['(assert (= carry_0_modadd_0_1_0 (or (and shift_0_0_1 key_1) (and shift_0_0_1 carry_0_modadd_0_1_1) (and key_1 carry_0_modadd_0_1_1))))',
              '(assert (= carry_0_modadd_0_1_1 (or (and shift_0_0_2 key_2) (and shift_0_0_2 carry_0_modadd_0_1_2) (and key_2 carry_0_modadd_0_1_2))))',
              ...
              '(assert (= carry_0_modadd_0_1_29 (or (and shift_0_0_30 key_30) (and shift_0_0_30 carry_0_modadd_0_1_30) (and key_30 carry_0_modadd_0_1_30))))',
              '(assert (= carry_0_modadd_0_1_30 (and shift_0_0_31 key_31)))',
              '(assert (= modadd_0_1_0 (xor shift_0_0_0 key_0 carry_0_modadd_0_1_0)))',
              '(assert (= modadd_0_1_1 (xor shift_0_0_1 key_1 carry_0_modadd_0_1_1)))',
              ...
              '(assert (= modadd_0_1_30 (xor shift_0_0_30 key_30 carry_0_modadd_0_1_30)))',
              '(assert (= modadd_0_1_31 (xor shift_0_0_31 key_31)))'])
        """
        _, input_ids = self._generate_input_ids()
        output_len, output_ids = self._generate_output_ids()
        num_of_addenda = self.description[1]
        # reformat of the in_ids
        inputs_ids = [input_ids[i * output_len: (i + 1) * output_len] for i in range(num_of_addenda)]
        # carries
        carries_ids = [[f'carry_{i}_{output_id}' for output_id in output_ids[:-1]]
                       for i in range(num_of_addenda - 1)]
        # reformat of the outputs_ids
        outputs_ids = [[f'modadd_output_{i}_{output_id}' for output_id in output_ids]
                       for i in range(num_of_addenda - 2)] + [output_ids]
        constraints = smt_modadd_seq(outputs_ids, inputs_ids, carries_ids)
        # flattening lists
        ids = [carry_id for carry_ids in carries_ids for carry_id in carry_ids]
        ids.extend([output_id for output_ids in outputs_ids for output_id in output_ids])
        return ids, constraints
