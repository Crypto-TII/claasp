
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


from claasp.components.modular_component import Modular
from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils


def cp_twoterms(input_1, input_2, out, component_name, input_length, cp_constraints, cp_declarations):
    cp_declarations.append(f'array[0..{input_length - 1}] of var 0..1:pre_minus_{input_2};')
    cp_declarations.append(f'array[0..{input_length - 1}] of var 0..1:minus_{input_2};')
    for i in range(input_length):
        cp_constraints.append(f'constraint pre_minus_{input_2}[{i}]=({input_2}[{i}] + 1) mod 2;')
    cp_constraints.append(f'constraint modadd(pre_minus_{input_2}, constant_{component_name}, minus_{input_2});')
    cp_constraints.append(f'constraint modadd({input_1},minus_{input_2},{out});')

    return cp_declarations, cp_constraints


class MODSUB(Modular):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size):
        super().__init__(current_round_number, current_round_number_of_components,
                         input_id_links, input_bit_positions, output_bit_size, 'modsub')

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

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=3)
            sage: modsub_component = raiden.component_from(0, 7)
            sage: modsub_component.cms_constraints()
            (['temp_carry_plaintext_32',
              'temp_carry_plaintext_33',
              'temp_carry_plaintext_34',
              ...
              'modsub_0_7_31 -modadd_0_4_31 temp_input_plaintext_63',
              'modsub_0_7_31 modadd_0_4_31 -temp_input_plaintext_63',
              '-modsub_0_7_31 -modadd_0_4_31 -temp_input_plaintext_63'])
        """
        return self.sat_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for Modular Addition component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=3)
            sage: modsub_component = raiden.component_from(0, 7)
            sage: modsub_component.cp_constraints()
            (['array[0..31] of var 0..1: constant_modsub_0_7= array1d(0..31,[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);',
              ...
              'array[0..31] of var 0..1:minus_pre_modsub_0_7_1;'],
             ['constraint pre_modsub_0_7_0[0]=modadd_0_4[0];',
              'constraint pre_modsub_0_7_0[1]=modadd_0_4[1];',
              'constraint pre_modsub_0_7_0[2]=modadd_0_4[2];',
              ...
              'constraint pre_minus_pre_modsub_0_7_1[31]=(pre_modsub_0_7_1[31] + 1) mod 2;',
              'constraint modadd(pre_minus_pre_modsub_0_7_1, constant_modsub_0_7, minus_pre_modsub_0_7_1);',
              'constraint modadd(pre_modsub_0_7_0,minus_pre_modsub_0_7_1,modsub_0_7);'])
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
        new_declaration = f'array[0..{output_size - 1}] of var 0..1: constant_{output_id_link}= ' \
                          f'array1d(0..{output_size - 1},['
        for i in range(output_size - 1):
            new_declaration = new_declaration + '0, '
        new_declaration = new_declaration + '1]);'
        cp_declarations.append(new_declaration)
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1: {output_id_link};')
        for i in range(num_add):
            cp_declarations.append(f'array[0..{input_len - 1}] of var 0..1:pre_{output_id_link}_{i};')
            for j in range(input_len):
                cp_constraints.append(f'constraint pre_{output_id_link}_{i}[{j}]={all_inputs[i * input_len + j]};')
        for i in range(num_add - 2):
            cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1:temp_{output_id_link}_{i};')
        if num_add == 2:
            cp_twoterms(f'pre_{output_id_link}_0', f'pre_{output_id_link}_1', str(output_id_link),
                        str(output_id_link), output_size, cp_constraints, cp_declarations)
        elif num_add > 2:
            cp_twoterms(f'pre_{output_id_link}_0', f'pre_{output_id_link}_1', f'temp_{output_id_link}_0',
                        str(output_id_link), output_size, cp_constraints, cp_declarations)
            for i in range(1, num_add - 2):
                cp_twoterms(f'pre_{output_id_link}_{i + 1}', f'temp_{output_id_link}_{i - 1}',
                            f'temp_{output_id_link}_{i}', str(output_id_link), output_size, cp_constraints,
                            cp_declarations)
                cp_twoterms(f'pre_{output_id_link}_{num_add - 1}', f'temp_{output_id_link}_{num_add - 3}',
                            str(output_id_link), str(output_id_link), output_size, cp_constraints,
                            cp_declarations)

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = bit_vector_MODSUB([{",".join(params)} ], '
                f'{self.description[1]}, {self.output_bit_size})']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_MODSUB({params})']

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for Modular Subtraction in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        .. WARNING::

            This method heavily relies on the fact that modular subtraction is always performed using two operands.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=3)
            sage: modsub_component = raiden.component_from(0, 7)
            sage: modsub_component.sat_constraints()
            (['temp_carry_plaintext_32',
              'temp_carry_plaintext_33',
              'temp_carry_plaintext_34',
              ...
              'modsub_0_7_31 -modadd_0_4_31 temp_input_plaintext_63',
              'modsub_0_7_31 modadd_0_4_31 -temp_input_plaintext_63',
              '-modsub_0_7_31 -modadd_0_4_31 -temp_input_plaintext_63'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        temp_carry_bit_ids = [f'temp_carry_{input_bit_ids[output_bit_len + i]}'
                              for i in range(output_bit_len - 1)]
        temp_input_bit_ids = [f'temp_input_{input_bit_ids[output_bit_len + i]}'
                              for i in range(output_bit_len)]
        carry_bit_ids = [f'carry_{output_bit_ids[i]}' for i in range(output_bit_len - 1)]
        constraints = []
        # carries complement 2
        for i in range(output_bit_len - 2):
            constraints.extend(sat_utils.cnf_carry_comp2(temp_carry_bit_ids[i],
                                                         input_bit_ids[output_bit_len + i + 1],
                                                         temp_carry_bit_ids[i + 1]))
        constraints.extend(sat_utils.cnf_inequality(temp_carry_bit_ids[output_bit_len - 2],
                                                    input_bit_ids[2 * output_bit_len - 1]))
        # results complement 2
        for i in range(output_bit_len - 1):
            constraints.extend(sat_utils.cnf_result_comp2(temp_input_bit_ids[i],
                                                          input_bit_ids[output_bit_len + i],
                                                          temp_carry_bit_ids[i]))
        constraints.extend(sat_utils.cnf_equivalent([temp_input_bit_ids[output_bit_len - 1],
                                                    input_bit_ids[2 * output_bit_len - 1]]))
        # carries
        for i in range(output_bit_len - 2):
            constraints.extend(sat_utils.cnf_carry(carry_bit_ids[i],
                                                   input_bit_ids[i + 1],
                                                   temp_input_bit_ids[i + 1],
                                                   carry_bit_ids[i + 1]))
        constraints.extend(sat_utils.cnf_and(carry_bit_ids[output_bit_len - 2],
                                             (input_bit_ids[output_bit_len - 1],
                                              temp_input_bit_ids[output_bit_len - 1])))
        # results
        for i in range(output_bit_len - 1):
            constraints.extend(sat_utils.cnf_xor(output_bit_ids[i],
                                                 [input_bit_ids[i],
                                                  temp_input_bit_ids[i],
                                                  carry_bit_ids[i]]))
        constraints.extend(sat_utils.cnf_xor(output_bit_ids[output_bit_len - 1],
                                             [input_bit_ids[output_bit_len - 1],
                                              temp_input_bit_ids[output_bit_len - 1]]))

        return temp_carry_bit_ids + temp_input_bit_ids + carry_bit_ids + output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts for Modular Subtraction in SMT CIPHER model.

        .. WARNING::

            This method heavily relies on the fact that modular subtraction is always performed using two operands.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=3)
            sage: modsub_component = raiden.component_from(0, 7)
            sage: modsub_component.smt_constraints()
            (['temp_carry_plaintext_32',
              'temp_carry_plaintext_33',
              ...
              'modsub_0_7_30',
              'modsub_0_7_31'],
             ['(assert (= temp_carry_plaintext_32 (and (not plaintext_33) temp_carry_plaintext_33)))',
              '(assert (= temp_carry_plaintext_33 (and (not plaintext_34) temp_carry_plaintext_34)))',
              ...
              '(assert (= modsub_0_7_30 (xor modadd_0_4_30 temp_input_plaintext_62 carry_modsub_0_7_30)))',
              '(assert (= modsub_0_7_31 (xor modadd_0_4_31 temp_input_plaintext_63)))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        temp_carry_bit_ids = [f'temp_carry_{input_bit_ids[output_bit_len + i]}'
                              for i in range(output_bit_len - 1)]
        temp_input_bit_ids = [f'temp_input_{input_bit_ids[output_bit_len + i]}'
                              for i in range(output_bit_len)]
        carry_bit_ids = [f'carry_{output_bit_ids[i]}' for i in range(output_bit_len - 1)]
        constraints = []

        # carries complement 2
        for i in range(output_bit_len - 2):
            operation = smt_utils.smt_and((smt_utils.smt_not(input_bit_ids[output_bit_len + i + 1]),
                                          temp_carry_bit_ids[i + 1]))
            equation = smt_utils.smt_equivalent((temp_carry_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))
        distinction = smt_utils.smt_distinct(temp_carry_bit_ids[output_bit_len - 2],
                                             input_bit_ids[2 * output_bit_len - 1])
        constraints.append(smt_utils.smt_assert(distinction))

        # results complement 2
        for i in range(output_bit_len - 1):
            operation = smt_utils.smt_xor((smt_utils.smt_not(input_bit_ids[output_bit_len + i]),
                                          temp_carry_bit_ids[i]))
            equation = smt_utils.smt_equivalent((temp_input_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))
        equation = smt_utils.smt_equivalent((temp_input_bit_ids[output_bit_len - 1],
                                            input_bit_ids[2 * output_bit_len - 1]))
        constraints.append(smt_utils.smt_assert(equation))

        # carries
        for i in range(output_bit_len - 2):
            operation = smt_utils.smt_carry(input_bit_ids[i + 1],
                                            temp_input_bit_ids[i + 1],
                                            carry_bit_ids[i + 1])
            equation = smt_utils.smt_equivalent((carry_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))
        operation = smt_utils.smt_and((input_bit_ids[output_bit_len - 1],
                                      temp_input_bit_ids[output_bit_len - 1]))
        equation = smt_utils.smt_equivalent((carry_bit_ids[output_bit_len - 2], operation))
        constraints.append(smt_utils.smt_assert(equation))

        # results
        for i in range(output_bit_len - 1):
            operation = smt_utils.smt_xor((input_bit_ids[i], temp_input_bit_ids[i], carry_bit_ids[i]))
            equation = smt_utils.smt_equivalent((output_bit_ids[i], operation))
            constraints.append(smt_utils.smt_assert(equation))
        operation = smt_utils.smt_xor((input_bit_ids[output_bit_len - 1],
                                      temp_input_bit_ids[output_bit_len - 1]))
        equation = smt_utils.smt_equivalent((output_bit_ids[output_bit_len - 1], operation))
        constraints.append(smt_utils.smt_assert(equation))

        return temp_carry_bit_ids + temp_input_bit_ids + carry_bit_ids + output_bit_ids, constraints
