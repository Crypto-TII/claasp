
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


import math
import subprocess
from math import log

from sage.arith.misc import is_power_of_two
from sage.crypto.sbox import SBox

from claasp.input import Input
from claasp.component import Component, free_input
from claasp.cipher_modules.models.sat.utils import constants
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_large_sboxes import (
    update_dictionary_that_contains_inequalities_for_large_sboxes,
    get_dictionary_that_contains_inequalities_for_large_sboxes)
from claasp.cipher_modules.models.milp.utils.generate_sbox_inequalities_for_trail_search import (
    update_dictionary_that_contains_inequalities_for_small_sboxes,
    get_dictionary_that_contains_inequalities_for_small_sboxes)

SIZE_SHOULD_BE_EQUAL = 'input_bit_size and output_bit_size should be equal.'


def check_table_feasibility(table, table_type, solver):
    occurrences = set(abs(value) for row in table.rows() for value in set(row)) - {0}
    for occurrence in occurrences:
        if not is_power_of_two(occurrence):
            raise ValueError(f'The S-box {table_type} of the cipher contains {occurrence} '
                             f'which is not a power of two. Currently, {solver} cannot handle it.')


def cp_update_ddt_valid_probabilities(cipher, component, word_size, cp_declarations,
                                      table_items, valid_probabilities, sbox_mant):
    input_size = int(component.input_bit_size)
    output_id_link = component.id
    description = component.description
    sbox = SBox(description)
    sbox_already_in = False
    for mant in sbox_mant:
        if description == mant[0]:
            sbox_already_in = True
    if not sbox_already_in:
        sbox_ddt = sbox.difference_distribution_table()
        for i in range(sbox_ddt.nrows()):
            set_of_occurrences = set(sbox_ddt.rows()[i])
            set_of_occurrences -= {0}
            valid_probabilities.update({round(100 * math.log2(2 ** input_size / occurrence))
                                        for occurrence in set_of_occurrences})
        sbox_mant.append((description, output_id_link))
    if cipher.is_spn():
        input_id_link = component.input_id_links[0]
        input_bit_positions = component.input_bit_positions[0]
        all_inputs = [f'{input_id_link}[{position}]' for position in input_bit_positions]
        for i in range(input_size // word_size):
            ineq_left_side = '+'.join([f'{all_inputs[i * word_size + j]}'
                                       for j in range(word_size)])
            new_declaration = f'constraint ({ineq_left_side} > 0) = word_{output_id_link}[{i}];'
            cp_declarations.append(new_declaration)
        cp_declarations.append(
            f'array[0..{input_size // word_size - 1}] of var 0..1: word_{output_id_link};')
        table_items.append(f'[word_{output_id_link}[s] | s in 0..{input_size // word_size - 1}]')


def cp_update_lat_valid_probabilities(component, valid_probabilities, sbox_mant):
    input_size = component.input_bit_size
    output_id_link = component.id
    description = component.description
    sbox = SBox(description)
    already_in = False
    for i in range(len(sbox_mant)):
        if description == sbox_mant[i][0]:
            already_in = True
    if not already_in:
        sbox_lat = sbox.linear_approximation_table()
        for i in range(sbox_lat.nrows()):
            set_of_occurrences = set(sbox_lat.rows()[i])
            set_of_occurrences -= {0}
            valid_probabilities.update({round(100 * math.log2(2 ** input_size / abs(occurrence)))
                                        for occurrence in set_of_occurrences})
        sbox_mant.append((description, output_id_link))


def milp_large_xor_probability_constraint_for_inequality(M, component_id, ineq, input_vars,
                                                         output_vars, proba, sbox_input_size, x):
    constraint = 0
    for i in range(sbox_input_size - 1, -1, -1):
        char = ineq[i]
        if char == "1":
            constraint += 1 - x[input_vars[i]]
        elif char == "0":
            constraint += x[input_vars[i]]
    for i in range(2 * sbox_input_size - 1, sbox_input_size - 1, -1):
        char = ineq[i]
        if char == "1":
            constraint += 1 - x[output_vars[i % sbox_input_size]]
        elif char == "0":
            constraint += x[output_vars[i % sbox_input_size]]
    constraint -= 1
    constraint += M * (1 - x[f"{component_id}_sboxproba_{proba}"])  # conditional constraints

    return constraint


def sat_build_table_template(table, get_hamming_weight_function, input_bit_len, output_bit_len):
    # create espresso input
    input_length = 2 * input_bit_len + output_bit_len
    espresso_input = [f'.i {input_length}', '.o 1']
    for i in range(table.nrows()):
        for j in range(table.ncols()):
            if table[i, j] != 0:
                input_diff = f'{i:0{input_bit_len}b}'
                output_diff = f'{j:0{output_bit_len}b}'
                hamming_weight = get_hamming_weight_function(input_bit_len, table[i, j])
                weight_vec = '0' * (input_bit_len - hamming_weight)
                weight_vec += '1' * hamming_weight
                espresso_input.append(f'{input_diff}{output_diff}{weight_vec} 1')
    espresso_input.append('.e')
    espresso_input = '\n'.join(espresso_input) + '\n'

    # execute espresso process
    espresso_process = subprocess.run(['espresso', '-epos'], input=espresso_input,
                                      capture_output=True, text=True)
    espresso_output = espresso_process.stdout.splitlines()

    # formatting template
    template = []
    for line in espresso_output[4:-1]:
        clause = tuple((int(line[i]), i) for i in range(input_length) if line[i] != '-')
        template.append(clause)

    return template


def smt_build_table_template(table, get_hamming_weight_function, input_bit_len, output_bit_len):
    return sat_build_table_template(table, get_hamming_weight_function, input_bit_len, output_bit_len)


def smt_get_sbox_probability_constraints(bit_ids, template):
    constraints = []
    for clause in template:
        literals = []
        for value in clause:
            literal = bit_ids[value[1]]
            if value[0]:
                literal = smt_utils.smt_not(literal)
            literals.append(literal)
        constraints.append(smt_utils.smt_assert(smt_utils.smt_or(literals)))

    return constraints


class SBOX(Component):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, s_box_description, suffix=''):
        component_id = f'sbox_{current_round_number}_{current_round_number_of_components}{suffix}'
        component_type = 'sbox'
        input_len = sum(map(len, input_bit_positions))
        description = s_box_description
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of SBOX polynomials.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: sbox_component = fancy.component_from(0, 0)
            sage: algebraic = AlgebraicModel(fancy)
            sage: sbox_component.algebraic_polynomials(algebraic)
            [sbox_0_0_y2 + sbox_0_0_x1,
             sbox_0_0_x0*sbox_0_0_y0 + sbox_0_0_x0*sbox_0_0_x3,
             ...
             sbox_0_0_y1*sbox_0_0_y3 + sbox_0_0_x0*sbox_0_0_x2,
             sbox_0_0_y2*sbox_0_0_y3 + sbox_0_0_x1*sbox_0_0_x2]
        """
        if self.type != "sbox":
            raise ValueError("component must be of a type sbox")

        S = SBox(self.description, big_endian=False)
        input_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(S.input_size())]
        output_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(S.output_size())]
        ring_R = model.ring()
        input_vars = list(map(ring_R, input_vars))
        output_vars = list(map(ring_R, output_vars))

        return S.polynomials(input_vars, output_vars)

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for S-BOX in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: present = PresentBlockCipher(number_of_rounds=3)
            sage: sbox_component = present.component_from(0, 2)
            sage: sbox_component.cms_constraints()
            (['sbox_0_2_0', 'sbox_0_2_1', 'sbox_0_2_2', 'sbox_0_2_3'],
             ['xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_0',
              'xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_1',
              ...
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_1',
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 sbox_0_2_2',
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_3'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model):
        return self.sat_xor_differential_propagation_constraints(model)

    def cms_xor_linear_mask_propagation_constraints(self, model):
        return self.sat_xor_linear_mask_propagation_constraints(model)

    def cp_constraints(self, sbox_mant):
        """
        Return lists of declarations and constraints for SBOX component for CP CIPHER model.

        INPUT:

        - ``sbox_mant`` -- **list of objects**; the list of the S-boxes already encountered so that there is no need to calculate the constraints again

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: midori = MidoriBlockCipher(number_of_rounds=3)
            sage: sbox_component = midori.component_from(0, 5)
            sage: sbox_component.cp_constraints([])
            (['array [1..16, 1..8] of int: table_sbox_0_5 = array2d(1..16, 1..8, [0,0,0,0,1,1,0,0,0,0,0,1,1,0,1,0,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,1,0,1,0,0,1,1,1,0,0,1,0,1,1,0,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,1,1,1,1,0,0,0,1,0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,0,1,1,0,1,1,0,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,0,1,0,0,1,1,1,1,0,1,1,0]);'],
             ['constraint table([xor_0_1[4]]++[xor_0_1[5]]++[xor_0_1[6]]++[xor_0_1[7]]++[sbox_0_5[0]]++[sbox_0_5[1]]++[sbox_0_5[2]]++[sbox_0_5[3]], table_sbox_0_5);'])
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        sbox = self.description
        already_in = False
        output_id_link_sost = output_id_link
        for mant in sbox_mant:
            if sbox == mant[0]:
                already_in = True
                output_id_link_sost = mant[1]
        cp_declarations = []
        if not already_in:
            bin_i = (','.join(f'{i:0{input_size}b}') for i in range(2 ** input_size))
            bin_sbox = (','.join(f'{sbox[i]:0{output_size}b}') for i in range(2 ** input_size))
            table_values = ','.join([f'{i},{s}' for i, s in zip(bin_i, bin_sbox)])
            sbox_declaration = f'array [1..{len(sbox)}, 1..{input_size + output_size}] of int: ' \
                               f'table_{output_id_link} = array2d(1..{len(sbox)}, 1..{input_size + output_size}, ' \
                               f'[{table_values}]);'
            cp_declarations.append(sbox_declaration)
            sbox_mant.append((sbox, output_id_link))
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'[{id_link}[{position}]]' for position in bit_positions])
        table_input = '++'.join(all_inputs)
        table_output = '++'.join([f'[{output_id_link}[{i}]]' for i in range(output_size)])
        new_constraint = f'constraint table({table_input}++{table_output}, table_{output_id_link_sost});'
        cp_constraints = [new_constraint]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_constraints(self, inverse=False):
        r"""
        Return lists of declarations and constraints for SBOX component for CP deterministic truncated xor differential.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: sbox_component = aes.component_from(0, 1)
            sage: sbox_component.cp_deterministic_truncated_xor_differential_constraints()
            ([],
             ['constraint if xor_0_0[0] == 0 /\\ xor_0_0[1] == 0 /\\ xor_0_0[2] == 0 /\\ xor_0_0[3] == 0 /\\ xor_0_0[4] == 0 /\\ xor_0_0[5] == 0 /\\ xor_0_0[6] == 0 /\\ xor_0_0[7] then forall(i in 0..7)(sbox_0_1[i] = 0) else forall(i in 0..7)(sbox_0_1[i] = 2) endif;'])
        """
        input_id_links = self.input_id_links
        output_id_link = self.id
        output_size = self.output_bit_size
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        cp_constraints = []
        all_inputs = []
        if inverse:
            for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                all_inputs.extend([f'{id_link}_inverse[{position}]' for position in bit_positions])
                elements = all_inputs[:]
                operation = ' == 0 /\\ '.join(elements)
                cp_constraints.append(
                    f'constraint if {operation}'
                    f' then forall(i in 0..{output_size - 1})({output_id_link}_inverse[i] = 0)'
                    f' else forall(i in 0..{output_size - 1})({output_id_link}_inverse[i] = 2) endif;')
        else:
            for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
                elements = all_inputs[:]
                operation = ' == 0 /\\ '.join(elements)
                cp_constraints.append(
                    f'constraint if {operation}'
                    f' then forall(i in 0..{output_size - 1})({output_id_link}[i] = 0)'
                    f' else forall(i in 0..{output_size - 1})({output_id_link}[i] = 2) endif;')

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists of declarations and constraints for SBOX component for CP wordwise deterministic truncated xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: sbox_component = aes.component_from(0, 1)
            sage: sbox_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)
            ([],
             ['constraint if xor_0_0_value[0]_active==0 then sbox_0_1_active[0] = 0 else sbox_0_1_active[0] = 2 endif;'])
        """
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_constraints = []
        cp_declarations = []
        all_inputs = []
        word_size = model.word_size
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}_value[{bit_positions[j * word_size] // word_size}]'
                               for j in range(len(bit_positions) // word_size)])
        for i, input_ in enumerate(all_inputs):
            cp_constraints.append(
                f'constraint if {input_}_active==0 then {output_id_link}_active[{i}] = 0'
                f' else {output_id_link}_active[{i}] = 2 endif;')

        return cp_declarations, cp_constraints

    def cp_xor_differential_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for SBOX component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: sbox_component = aes.component_from(0, 1)
            sage: sbox_component.cp_xor_differential_first_step_constraints(cp)
            (['array[0..0] of var 0..1: sbox_0_1;'],
             ['constraint sbox_0_1[0] = xor_0_0[0];'])
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        all_inputs = []
        cp_constraints = []
        word_size = model.word_size
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            for j in range(len(bit_positions) // word_size):
                all_inputs.append(f'{id_link}[{bit_positions[j * word_size] // word_size}]')
                model.input_sbox.append((f'{id_link}[{bit_positions[j * word_size] // word_size}]',
                                         input_size // word_size - 1))
                model.table_of_solutions_length += input_size // word_size
        cp_declarations = [f'array[0..{(output_size - 1) // word_size}] of var 0..1: {output_id_link};']
        cp_constraints.extend([f'constraint {output_id_link}[{i}] = {input_};' for i, input_ in enumerate(all_inputs)])

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        return self.cp_xor_differential_first_step_constraints(model)

    def cp_xor_differential_propagation_constraints(self, model):
        """
        Return lists of declarations and constraints for the probability of SBOX component for CP xor differential probability.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: midori = MidoriBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(midori)
            sage: sbox_component = midori.component_from(0, 5)
            sage: sbox_component.cp_xor_differential_propagation_constraints(cp)[1:]
            (['constraint table([xor_0_1[4]]++[xor_0_1[5]]++[xor_0_1[6]]++[xor_0_1[7]]++[sbox_0_5[0]]++[sbox_0_5[1]]++[sbox_0_5[2]]++[sbox_0_5[3]]++[p[0]], DDT_sbox_0_5);'],)
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        description = self.description
        sbox = SBox(description)
        cp_declarations = []
        already_in = False
        output_id_link_sost = output_id_link
        for mant in model.sbox_mant:
            if description == mant[0]:
                already_in = True
                output_id_link_sost = mant[1]
        if not already_in:
            sbox_ddt = sbox.difference_distribution_table()
            dim_ddt = len([i for i in sbox_ddt.list() if i])
            ddt_entries = []
            for i in range(sbox_ddt.nrows()):
                for j in range(sbox_ddt.ncols()):
                    if sbox_ddt[i][j]:
                        sep_bin_i = ','.join(f'{i:0{input_size}b}')
                        sep_bin_j = ','.join(f'{j:0{output_size}b}')
                        log_of_prob = round(100 * math.log2((2 ** input_size) / sbox_ddt[i][j]))
                        ddt_entries.append(f'{sep_bin_i},{sep_bin_j},{log_of_prob}')
            ddt_values = ','.join(ddt_entries)
            sbox_declaration = f'array [1..{dim_ddt}, 1..{input_size + output_size + 1}] of int: ' \
                               f'DDT_{output_id_link} = array2d(1..{dim_ddt}, 1..{input_size + output_size + 1}, ' \
                               f'[{ddt_values}]);'
            cp_declarations.append(sbox_declaration)
            model.sbox_mant.append((description, output_id_link))
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'[{id_link}[{position}]]' for position in bit_positions])
        table_input = '++'.join(all_inputs)
        table_output = '++'.join([f'[{output_id_link}[{i}]]' for i in range(output_size)])
        constraint = f'constraint table({table_input}++{table_output}++[p[{model.c}]], DDT_{output_id_link_sost});'
        cp_constraints = [constraint]
        model.component_and_probability[output_id_link] = model.c
        model.c += 1

        return cp_declarations, cp_constraints

    def cp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of declarations and constraints for the probability of SBOX component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: midori = MidoriBlockCipher()
            sage: cp = CpModel(midori)
            sage: sbox_component = midori.component_from(0, 5)
            sage: sbox_component.cp_xor_linear_mask_propagation_constraints(cp)[1:]
            (['constraint table([sbox_0_5_i[0]]++[sbox_0_5_i[1]]++[sbox_0_5_i[2]]++[sbox_0_5_i[3]]++[sbox_0_5_o[0]]++[sbox_0_5_o[1]]++[sbox_0_5_o[2]]++[sbox_0_5_o[3]]++[p[0]],LAT_sbox_0_5);'],)
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        description = self.description
        sbox = SBox(description)
        cp_declarations = []
        cp_constraints = []
        already_in = 0
        output_id_link_sost = output_id_link
        sbox_mant = model.sbox_mant
        for i in range(len(sbox_mant)):
            if description == sbox_mant[i][0]:
                already_in = 1
                output_id_link_sost = sbox_mant[i][1]
        if already_in == 0:
            size = 0
            sbox_lat = sbox.linear_approximation_table()
            sbox_declaration = '['
            for i in range(sbox_lat.nrows()):
                for j in range(sbox_lat.ncols()):
                    sep_bin_i = ','.join(f'{i:0{input_size}b}')
                    sep_bin_j = ','.join(f'{j:0{output_size}b}')
                    if sbox_lat[i, j] != 0:
                        size += 1
                        bias = round(100 * math.log2(abs(pow(2, input_size - 1) / sbox_lat[i, j])))
                        sbox_declaration = sbox_declaration + f'{sep_bin_i},{sep_bin_j},{bias},'
            pre_declaration = f'array [1..{size},1..{input_size + output_size + 1}] of int: ' \
                              f'LAT_{output_id_link}=array2d(1..{size},1..{input_size + output_size + 1},'
            sbox_declaration = pre_declaration + sbox_declaration[:-1] + ']);'
            cp_declarations.append(sbox_declaration)
            sbox_mant.append((description, output_id_link))
        cp_declarations.append(f'array[0..{input_size - 1}] of var 0..1: {output_id_link}_i;')
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1: {output_id_link}_o;')
        new_constraint = 'constraint table('
        for i in range(input_size):
            new_constraint = new_constraint + f'[{output_id_link}_i[{i}]]++'
        for i in range(output_size):
            new_constraint = new_constraint + f'[{output_id_link}_o[{i}]]++'
        new_constraint = new_constraint + f'[p[{model.c}]],LAT_{output_id_link_sost});'
        cp_constraints.append(new_constraint)
        model.component_and_probability[output_id_link] = model.c
        model.c = model.c + 1

        return cp_declarations, cp_constraints

    def generate_sbox_sign_lat(self):
        input_size = pow(2, self.input_bit_size)
        output_size = pow(2, self.output_bit_size)
        description = self.description
        sbox = SBox(description)
        sbox_lat = sbox.linear_approximation_table()
        sbox_sign_lat = [[0 for _ in range(input_size)] for _ in range(output_size)]
        for i in range(input_size):
            for j in range(output_size):
                if sbox_lat[i][j] != 0:
                    sbox_sign_lat[i][j] = sbox_lat[i][j] / (abs(sbox_lat[i][j]))

        return sbox_sign_lat

    def get_bit_based_c_code(self, verbosity):
        sbox_code = []
        self.select_bits(sbox_code)

        sbox_code.append(
            f'\tsubstitution_list = '
            f'(uint64_t[]) {{{", ".join([str(x) for x in self.description])}}};')
        sbox_code.append(
            f'\tBitString* {self.id} = '
            f'SBOX(input, {self.output_bit_size}, substitution_list);\n')

        if verbosity:
            self.print_values(sbox_code)

        free_input(sbox_code)

        return sbox_code

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        sbox_params = [f'bit_vector_select_word({self.input_id_links[i]},  {self.input_bit_positions[i]})'
                       for i in range(len(self.input_id_links))]
        return [f'  {self.id} = bit_vector_SBOX(bit_vector_CONCAT([{",".join(sbox_params)} ]), '
                f'np.array({self.description}, dtype=np.uint8))']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_SBOX({params}, np.array({self.description}, dtype=np.uint8))']

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        # TODO: consider the option for sbox
        return ['\t//// TODO']

    def milp_large_xor_differential_probability_constraints(self, binary_variable, integer_variable,
                                                            non_linear_component_id):
        """
        Return lists of variables and constrains modeling SBOX component, with input bit size less or equal to 6.

        .. NOTE::

            This is for MILP large xor differential probability. Constraints extracted from
          https://tosc.iacr.org/index.php/ToSC/article/view/805/759.

        INPUT:

        - ``binary_variable`` -- **boolean MIPVariable object**
        - ``integer_variable`` -- **boolean MIPVariable object**
        - ``non_linear_component_id`` -- **string**

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: from sage.crypto.sbox import SBox
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: milp = MilpModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = aes.component_from(0, 1)
            sage: from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_large_sboxes import delete_dictionary_that_contains_inequalities_for_large_sboxes
            sage: delete_dictionary_that_contains_inequalities_for_large_sboxes()
            sage: variables, constraints = sbox_component.milp_large_xor_differential_probability_constraints(milp.binary_variable, milp.integer_variable, milp._non_linear_component_id) # long
            ...
            sage: variables # long
            [('x[xor_0_0_0]', x_0),
            ('x[xor_0_0_1]', x_1),
            ...
            ('x[sbox_0_1_6]', x_14),
            ('x[sbox_0_1_7]', x_15)]
            sage: constraints[:3] # long
            [x_0 + x_1 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 <= 8*x_16,
            1 - x_0 - x_1 - x_2 - x_3 - x_4 - x_5 - x_6 - x_7 <= 8 - 8*x_16,
            x_8 <= x_16]
        """
        if self.output_bit_size != self.input_bit_size:
            raise ValueError(SIZE_SHOULD_BE_EQUAL)

        x = binary_variable
        p = integer_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        component_id = self.id
        non_linear_component_id.append(component_id)
        sbox = SBox(self.description)
        sbox_input_size = sbox.input_size()
        update_dictionary_that_contains_inequalities_for_large_sboxes(sbox, analysis="differential")
        dict_product_of_sum = get_dictionary_that_contains_inequalities_for_large_sboxes(analysis="differential")

        # condition to know if sbox is active or not
        constraints.append(
            sbox_input_size * x[f"{component_id}_active"] >= sum(x[input_vars[i]] for i in range(sbox_input_size)))
        constraints.append(
            sbox_input_size * (1 - x[f"{component_id}_active"]) >= -sum(
                x[input_vars[i]] for i in range(sbox_input_size)) + 1)
        constraints += [x[f"{component_id}_active"] >= x[output_vars[i]] for i in range(sbox_input_size)]
        # mip.add_constraint(sum(x[output_vars[i]] for i in range(sbox.input_size())) >= x[id + "_active"])

        M = 10 * sbox_input_size
        constraint_choice_proba = 0
        constraint_compute_proba = 0
        for proba in dict_product_of_sum[str(sbox)].keys():
            for ineq in dict_product_of_sum[str(sbox)][proba]:
                constraint = milp_large_xor_probability_constraint_for_inequality(M, component_id, ineq,
                                                                                  input_vars, output_vars,
                                                                                  proba, sbox_input_size, x)
                constraints.append(constraint >= 0)

            constraint_choice_proba += x[f"{component_id}_sboxproba_{proba}"]
            constraint_compute_proba += \
                x[f"{component_id}_sboxproba_{proba}"] * 10 * round(-log(proba / 2 ** sbox_input_size, 2), 1)

        constraints.append(constraint_choice_proba == x[f"{component_id}_active"])
        constraints.append(p[f"{component_id}_probability"] == constraint_compute_proba)

        return variables, constraints

    def milp_large_xor_linear_probability_constraints(self, binary_variable, integer_variable, non_linear_component_id):
        """
        Return lists of variables and constrains modeling SBOX component, with input bit size less or equal to 6.

        .. NOTE::

            This is for MILP large xor linear probability. Constraints extracted from
          https://tosc.iacr.org/index.php/ToSC/article/view/805/759.

        INPUT:

        - ``binary_variable`` -- **boolean MIPVariable object**
        - ``integer_variable`` -- **integer MIPVariable object**
        - ``non_linear_component_id`` -- **string**

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: milp = MilpModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = aes.component_from(0, 1)
            sage: variables, constraints = sbox_component.milp_large_xor_linear_probability_constraints(milp.binary_variable, milp.integer_variable, milp._non_linear_component_id) # very long
            ...
            sage: variables
            [('x[sbox_0_1_0_i]', x_0),
             ('x[sbox_0_1_1_i]', x_1),
             ...
             ('x[sbox_0_1_6_o]', x_14),
             ('x[sbox_0_1_7_o]', x_15)]
            sage: constraints
            [x_0 + x_1 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 <= 8*x_16,
            1 - x_0 - x_1 - x_2 - x_3 - x_4 - x_5 - x_6 - x_7 <= 8 - 8*x_16,
            ...
            x_17 + x_18 + x_19 + x_20 + x_21 + x_22 + x_23 + x_24 + x_25 + x_26 + x_27 + x_28 + x_29 + x_30 + x_31 + x_32 == x_16,
            x_33 == 60*x_17 + 50*x_18 + 44*x_19 + 40*x_20 + 37*x_21 + 34*x_22 + 32*x_23 + 30*x_24 + 30*x_25 + 32*x_26 + 34*x_27 + 37*x_28 + 40*x_29 + 44*x_30 + 50*x_31 + 60*x_32]
        """
        if self.output_bit_size != self.input_bit_size:
            raise ValueError(SIZE_SHOULD_BE_EQUAL)

        x = binary_variable
        p = integer_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        component_id = self.id
        non_linear_component_id.append(component_id)
        sbox = SBox(self.description)
        sbox_input_size = sbox.input_size()
        update_dictionary_that_contains_inequalities_for_large_sboxes(sbox, analysis="linear")
        dict_product_of_sum = get_dictionary_that_contains_inequalities_for_large_sboxes(analysis="linear")

        # condition to know if sbox is active or not
        constraints.append(
            sbox_input_size * x[f"{component_id}_active"] >= sum(x[input_vars[i]] for i in range(sbox_input_size)))
        constraints.append(
            sbox_input_size * (1 - x[f"{component_id}_active"]) >=
            -sum(x[input_vars[i]] for i in range(sbox_input_size)) + 1)
        constraints += [x[f"{component_id}_active"] >= x[output_vars[i]] for i in range(sbox_input_size)]

        M = 10 * sbox_input_size
        constraint_choice_proba = 0
        constraint_compute_proba = 0
        for proba in dict_product_of_sum[str(sbox)].keys():
            for ineq in dict_product_of_sum[str(sbox)][proba]:
                constraint = milp_large_xor_probability_constraint_for_inequality(M, component_id, ineq,
                                                                                  input_vars,
                                                                                  output_vars, proba,
                                                                                  sbox_input_size, x)
                constraints.append(constraint >= 0)

            constraint_choice_proba += x[f"{component_id}_sboxproba_{proba}"]
            constraint_compute_proba += (x[f"{component_id}_sboxproba_{proba}"] *
                                         10 * round(-log(abs(proba) / (2 ** (sbox_input_size - 1)), 2), 1))
        constraints.append(constraint_choice_proba == x[f"{component_id}_active"])
        constraints.append(p[f"{component_id}_probability"] == constraint_compute_proba)

        return variables, constraints

    def milp_small_xor_differential_probability_constraints(self, binary_variable, integer_variable,
                                                            non_linear_component_id):
        """
        Return a list of variables and a list of constrains modeling a component of type SBOX.

        .. NOTE::

            This is for MILP small xor differential probability. Constraints extracted from
          https://eprint.iacr.org/2014/747.pdf and https://tosc.iacr.org/index.php/ToSC/article/view/805/759

        INPUT:

        - ``binary_variable`` -- **boolean MIPVariable object**
        - ``integer_variable`` -- **integer MIPVariable object**
        - ``non_linear_component_id`` -- **string**

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: present = PresentBlockCipher(number_of_rounds=6)
            sage: milp = MilpModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = present.component_from(0, 1)
            sage: variables, constraints = sbox_component.milp_small_xor_differential_probability_constraints(milp.binary_variable, milp.integer_variable, milp._non_linear_component_id)
            ...
            sage: variables
            [('x[xor_0_0_0]', x_0),
            ('x[xor_0_0_1]', x_1),
            ...
            ('x[sbox_0_1_2]', x_6),
            ('x[sbox_0_1_3]', x_7)]
            sage: constraints
            [x_8 <= x_0 + x_1 + x_2 + x_3,
            x_0 <= x_8,
            ...
            x_9 + x_10 == x_8,
            x_11 == 30*x_9 + 20*x_10]
        """
        if self.output_bit_size != self.input_bit_size:
            raise ValueError(SIZE_SHOULD_BE_EQUAL)

        x = binary_variable
        p = integer_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        non_linear_component_id.append(self.id)
        sbox = SBox(self.description)
        update_dictionary_that_contains_inequalities_for_small_sboxes(sbox, analysis="differential")
        dictio = get_dictionary_that_contains_inequalities_for_small_sboxes(analysis="differential")
        dict_inequalities = dictio[f"{sbox}"]
        input_size = self.input_bit_size

        # condition to know if sbox is active or not
        constraints.append(x[f"{self.id}_active"] <= sum(x[input_vars[i]] for i in range(input_size)))
        for i in range(input_size):
            constraints.append(x[f"{self.id}_active"] >= x[input_vars[i]])
        for i in range(input_size):
            constraints.append(x[f"{self.id}_active"] >= x[output_vars[i]])
        # mip.add_constraint(sum(x[output_vars[i]] for i in range(sbox.input_size())) >= x[id + "_active"])

        M = 10 * input_size
        dict_constraints = {}
        for proba in dict_inequalities:
            dict_constraints[proba] = []
            for ineq in dict_inequalities[proba]:
                dict_constraints[proba].append(sum(x[input_vars[i]] * ineq[i + 1] for i in range(len(input_vars))) +
                                               sum(x[output_vars[i]] * ineq[i + 1 + len(input_vars)] for i in
                                                   range(len(output_vars))) +
                                               ineq[0] + M * (1 - x[f"{self.id}_proba_{proba}"]) >= 0)

        for proba in dict_constraints:
            constraints.extend(dict_constraints[proba])

        constraints.append(
            sum(x[f"{self.id}_proba_{proba}"] for proba in dict_constraints) == x[f"{self.id}_active"])
        constraints.append(p[f"{self.id}_probability"] == 10 * sum(
            x[f"{self.id}_proba_{proba}"] * (-log(proba / 2 ** sbox.input_size(), 2)) for proba in
            dict_constraints))

        return variables, constraints

    def milp_small_xor_linear_probability_constraints(self, binary_variable, integer_variable, non_linear_component_id):
        """
        Return a list of variables and a list of constrains modeling a component of type Sbox.

        .. NOTE::

            This is for MILP small xor linear probability. Constraints extracted from
          https://eprint.iacr.org/2014/747.pdf (Appendix A) and
          https://tosc.iacr.org/index.php/ToSC/article/view/805/759

        INPUT:

        - ``binary_variable`` -- **MIPVariable object**
        - ``integer_variable`` -- **MIPVariable object**
        - ``non_linear_component_id`` -- **list**

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: present = PresentBlockCipher(number_of_rounds=6)
            sage: milp = MilpModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = present.component_from(0, 1)
            sage: variables, constraints = sbox_component.milp_small_xor_linear_probability_constraints(milp.binary_variable, milp.integer_variable, milp._non_linear_component_id)
            ...
            sage: variables
            [('x[sbox_0_1_0_i]', x_0),
            ('x[sbox_0_1_1_i]', x_1),
            ...
            ('x[sbox_0_1_2_o]', x_6),
            ('x[sbox_0_1_3_o]', x_7)]
            sage: constraints
            [x_8 <= x_4 + x_5 + x_6 + x_7,
            x_0 <= x_8,
            ...
            x_9 + x_10 + x_11 + x_12 == x_8,
            x_13 == 20*x_9 + 10*x_10 + 10*x_11 + 20*x_12]
        """
        if self.output_bit_size != self.input_bit_size:
            raise ValueError(SIZE_SHOULD_BE_EQUAL)

        x = binary_variable
        p = integer_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        component_id = self.id
        non_linear_component_id.append(component_id)
        sbox = SBox(self.description)
        update_dictionary_that_contains_inequalities_for_small_sboxes(sbox, analysis="linear")
        dictio = get_dictionary_that_contains_inequalities_for_small_sboxes(analysis="linear")
        dict_inequalities = dictio[f"{sbox}"]
        input_size = self.input_bit_size
        output_size = self.output_bit_size

        # condition to know if sbox is active or not
        # from https://eprint.iacr.org/2014/747.pdf (Appendix A)
        constraints.append(x[f"{component_id}_active"] <= sum(x[output_vars[i]] for i in range(output_size)))
        for i in range(input_size):
            constraints.append(x[f"{component_id}_active"] >= x[input_vars[i]])
        for i in range(output_size):
            constraints.append(x[f"{component_id}_active"] >= x[output_vars[i]])

        # Big-M Reformulation method as used in 4.1 of
        # https://tosc.iacr.org/index.php/ToSC/article/view/805/759
        M = 10 * input_size
        dict_constraints = {}
        for proba in dict_inequalities:
            dict_constraints[proba] = []
            for ineq in dict_inequalities[proba]:
                dict_constraints[proba].append(sum(x[input_vars[i]] * ineq[i + 1] for i in range(len(input_vars))) +
                                               sum(x[output_vars[i]] * ineq[i + 1 + len(input_vars)]
                                                   for i in range(len(output_vars))) +
                                               ineq[0] + M * (1 - x[f"{component_id}_proba_{proba}"]) >= 0)

        for proba in dict_constraints:
            constraints.extend(dict_constraints[proba])

        constraints.append(
            sum(x[f"{component_id}_proba_{proba}"] for proba in dict_constraints) == x[f"{component_id}_active"])

        # correlation[i,j] =  2p[i,j] - 1, where p[i,j] = LAT[i,j] / 2^n + 1/2
        constraints.append(p[f"{component_id}_probability"] == 10 * sum(x[f"{component_id}_proba_{proba}"] *
                                                                        (log((2 ** (sbox.input_size() - 1)) / abs(
                                                                            proba), 2)) for proba in dict_constraints))

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return list of variables and constrains modeling a component of type SBOX for MILP xor differential probability.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: present = PresentBlockCipher(number_of_rounds=6)
            sage: milp = MilpModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = present.component_from(0, 1)
            sage: variables, constraints = sbox_component.milp_xor_differential_propagation_constraints(milp)
            ...
            sage: variables
            [('x[xor_0_0_0]', x_0),
            ('x[xor_0_0_1]', x_1),
            ...
            ('x[sbox_0_1_2]', x_6),
            ('x[sbox_0_1_3]', x_7)]
            sage: constraints
            [x_0 + x_1 + x_2 + x_3 <= 4*x_8,
            1 - x_0 - x_1 - x_2 - x_3 <= 4 - 4*x_8,
            ...
            x_9 + x_10 == x_8,
            x_11 == 30*x_9 + 20*x_10]
        """
        binary_variable = model.binary_variable
        integer_variable = model.integer_variable
        non_linear_component_id = model.non_linear_component_id
        variables, constraints = self.milp_large_xor_differential_probability_constraints(binary_variable,
                                                                                              integer_variable,
                                                                                              non_linear_component_id)

        return variables, constraints

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of variables and constraints for the probability of the SBOX component for the MILP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: present = PresentBlockCipher(number_of_rounds=6)
            sage: milp = MilpModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = present.component_from(0, 1)
            sage: variables, constraints = sbox_component.milp_xor_linear_mask_propagation_constraints(milp)
            ...
            sage: variables
            [('x[sbox_0_1_0_i]', x_0),
            ('x[sbox_0_1_1_i]', x_1),
            ...
            ('x[sbox_0_1_2_o]', x_6),
            ('x[sbox_0_1_3_o]', x_7)]
            sage: constraints
            [x_8 <= x_4 + x_5 + x_6 + x_7,
            x_0 <= x_8,
            ...
            x_9 + x_10 + x_11 + x_12 == x_8,
            x_13 == 20*x_9 + 10*x_10 + 10*x_11 + 20*x_12]
        """
        binary_variable = model.binary_variable
        integer_variable = model.integer_variable
        non_linear_component_id = model.non_linear_component_id
        if self.output_bit_size <= 4:
            variables, constraints = self.milp_small_xor_linear_probability_constraints(binary_variable,
                                                                                        integer_variable,
                                                                                        non_linear_component_id)
        else:
            variables, constraints = self.milp_large_xor_linear_probability_constraints(binary_variable,
                                                                                        integer_variable,
                                                                                        non_linear_component_id)
        return variables, constraints

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for S-BOX in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: present = PresentBlockCipher(number_of_rounds=3)
            sage: sbox_component = present.component_from(0, 2)
            sage: sbox_component.sat_constraints()
            (['sbox_0_2_0', 'sbox_0_2_1', 'sbox_0_2_2', 'sbox_0_2_3'],
             ['xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_0',
              'xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_1',
              ...
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_1',
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 sbox_0_2_2',
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_3'])
        """
        input_bit_len, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        sbox_values = self.description
        constraints = []
        for i in range(2 ** input_bit_len):
            input_minus = ['-' * (i >> j & 1) for j in reversed(range(input_bit_len))]
            current_input_bit_ids = [f'{input_minus[j]}{input_bit_ids[j]}'
                                     for j in range(input_bit_len)]
            output_minus = ['-' * ((sbox_values[i] >> j & 1) ^ 1)
                            for j in reversed(range(output_bit_len))]
            current_output_bit_ids = [f'{output_minus[j]}{output_bit_ids[j]}'
                                      for j in range(output_bit_len)]
            input_constraint = ' '.join(current_input_bit_ids)
            for j in range(output_bit_len):
                constraint = f'{input_constraint} {current_output_bit_ids[j]}'
                constraints.append(constraint)

        return output_bit_ids, constraints

    def sat_xor_differential_propagation_constraints(self, model):
        """
        Return a list of variables and a list of clauses for a generic S-BOX in SAT XOR DIFFERENTIAL model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_model import SatModel
            sage: present = PresentBlockCipher(number_of_rounds=3)
            sage: sbox_component = present.component_from(0, 2)
            sage: sat = SatModel(present)
            sage: sbox_component.sat_xor_differential_propagation_constraints(sat)
            (['sbox_0_2_0',
              'sbox_0_2_1',
              'sbox_0_2_2',
              ...
              'hw_sbox_0_2_2 -hw_sbox_0_2_3',
              'xor_0_0_5 xor_0_0_6 sbox_0_2_0 sbox_0_2_2 -hw_sbox_0_2_1',
              '-hw_sbox_0_2_0'])
        """
        input_bit_len, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(input_bit_len)]
        sbox_values = self.description
        sboxes_ddt_templates = model.sboxes_ddt_templates

        # if optimized SAT DDT template is not initialized in instance fields, compute it
        if f'{sbox_values}' not in sboxes_ddt_templates:
            ddt = SBox(sbox_values).difference_distribution_table()

            check_table_feasibility(ddt, 'DDT', 'SAT')

            get_hamming_weight_function = (
                    lambda input_bit_len, entry: input_bit_len - int(math.log2(entry)))
            template = sat_build_table_template(
                    ddt, get_hamming_weight_function, input_bit_len, output_bit_len)
            sboxes_ddt_templates[f'{sbox_values}'] = template

        bit_ids = input_bit_ids + output_bit_ids + hw_bit_ids
        template = sboxes_ddt_templates[f'{sbox_values}']
        constraints = []
        for clause in template:
            literals = ['-' * value[0] + bit_ids[value[1]] for value in clause]
            constraints.append(' '.join(literals))

        return output_bit_ids + hw_bit_ids, constraints

    def sat_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of clauses for S-BOX in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_model import SatModel
            sage: present = PresentBlockCipher(number_of_rounds=3)
            sage: sbox_component = present.component_from(0, 2)
            sage: sat = SatModel(present)
            sage: sbox_component.sat_xor_linear_mask_propagation_constraints(sat)
            (['sbox_0_2_0_i',
              'sbox_0_2_1_i',
              'sbox_0_2_2_i',
              ...
              '-sbox_0_2_0_i -sbox_0_2_1_i sbox_0_2_2_i sbox_0_2_1_o -hw_sbox_0_2_2_o',
              '-hw_sbox_0_2_1_o',
              '-hw_sbox_0_2_0_o'])
        """
        input_bit_len, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(input_bit_len)]
        sbox_values = self.description
        sboxes_lat_templates = model.sboxes_lat_templates

        # if optimized SAT LAT template is not initialized in instance fields, compute it
        if f'{sbox_values}' not in sboxes_lat_templates:
            lat = SBox(sbox_values).linear_approximation_table()

            check_table_feasibility(lat, 'LAT', 'SAT')

            get_hamming_weight_function = (
                    lambda input_bit_len, entry: input_bit_len - int(math.log2(abs(entry))) - 1)
            template = sat_build_table_template(
                    lat, get_hamming_weight_function, input_bit_len, output_bit_len)
            sboxes_lat_templates[f'{sbox_values}'] = template

        bit_ids = input_bit_ids + output_bit_ids + hw_bit_ids
        template = sboxes_lat_templates[f'{sbox_values}']
        constraints = []
        for clause in template:
            literals = ['-' * value[0] + bit_ids[value[1]] for value in clause]
            constraints.append(' '.join(literals))

        return bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts for S-BOX in SMT CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: present = PresentBlockCipher(key_bit_size=80, number_of_rounds=3)
            sage: sbox_component = present.component_from(0, 1)
            sage: sbox_component.smt_constraints()
            (['sbox_0_1_0', 'sbox_0_1_1', 'sbox_0_1_2', 'sbox_0_1_3'],
             ['(assert (=> (and (not xor_0_0_0) (not xor_0_0_1) (not xor_0_0_2) (not xor_0_0_3)) (and sbox_0_1_0 sbox_0_1_1 (not sbox_0_1_2) (not sbox_0_1_3))))',
              '(assert (=> (and (not xor_0_0_0) (not xor_0_0_1) (not xor_0_0_2) xor_0_0_3) (and (not sbox_0_1_0) sbox_0_1_1 (not sbox_0_1_2) sbox_0_1_3)))',
              ...
              '(assert (=> (and xor_0_0_0 xor_0_0_1 (not xor_0_0_2) xor_0_0_3) (and (not sbox_0_1_0) sbox_0_1_1 sbox_0_1_2 sbox_0_1_3)))',
              '(assert (=> (and xor_0_0_0 xor_0_0_1 xor_0_0_2 (not xor_0_0_3)) (and (not sbox_0_1_0) (not sbox_0_1_1) (not sbox_0_1_2) sbox_0_1_3)))',
              '(assert (=> (and xor_0_0_0 xor_0_0_1 xor_0_0_2 xor_0_0_3) (and (not sbox_0_1_0) (not sbox_0_1_1) sbox_0_1_2 (not sbox_0_1_3))))'])
        """
        input_bit_len, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        sbox_values = self.description
        constraints = []
        for i in range(len(sbox_values)):
            input_difference_lits = [input_bit_ids[j]
                                     if i >> (input_bit_len - 1 - j) & 1
                                     else smt_utils.smt_not(input_bit_ids[j])
                                     for j in range(input_bit_len)]
            input_difference = smt_utils.smt_and(input_difference_lits)
            output_difference_lits = [output_bit_ids[j]
                                      if sbox_values[i] >> (output_bit_len - 1 - j) & 1
                                      else smt_utils.smt_not(output_bit_ids[j])
                                      for j in range(output_bit_len)]
            output_difference = smt_utils.smt_and(output_difference_lits)
            implication = smt_utils.smt_implies(input_difference, output_difference)
            constraints.append(smt_utils.smt_assert(implication))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model):
        """
        Return a variable list and SMT-LIB list asserts for S-BOX in SMT XOR DIFFERENTIAL model [AK2019]_.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_model import SmtModel
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: smt = SmtModel(fancy)
            sage: sbox_component = fancy.component_from(0, 5)
            sage: sbox_component.smt_xor_differential_propagation_constraints(smt)
            (['sbox_0_5_0',
              'sbox_0_5_1',
              ...
              'hw_sbox_0_5_2',
              'hw_sbox_0_5_3'],
             ['(assert (or (not plaintext_20) sbox_0_5_3))',
              '(assert (or plaintext_20 (not sbox_0_5_3)))',
              ...
              '(assert (or (not hw_sbox_0_5_1)))',
              '(assert (or (not hw_sbox_0_5_0)))'])
        """
        input_bit_len, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(input_bit_len)]
        sbox_values = self.description
        sboxes_ddt_templates = model.sboxes_ddt_templates

        # if optimized DDT template is not initialized in instance fields, compute it
        if f'{sbox_values}' not in sboxes_ddt_templates:
            ddt = SBox(sbox_values).difference_distribution_table()

            check_table_feasibility(ddt, 'DDT', 'SMT')

            get_hamming_weight_function = (
                    lambda input_bit_len, entry: input_bit_len - int(math.log2(entry)))
            template = smt_build_table_template(
                    ddt, get_hamming_weight_function, input_bit_len, output_bit_len)
            sboxes_ddt_templates[f'{sbox_values}'] = template

        bit_ids = input_bit_ids + output_bit_ids + hw_bit_ids
        template = sboxes_ddt_templates[f'{sbox_values}']
        constraints = smt_get_sbox_probability_constraints(bit_ids, template)

        return output_bit_ids + hw_bit_ids, constraints

    def smt_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a variable list and SMT-LIB list asserts for S-BOX in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_model import SmtModel
            sage: present = PresentBlockCipher(number_of_rounds=3)
            sage: sbox_component = present.component_from(0, 2)
            sage: smt = SmtModel(present)
            sage: sbox_component.smt_xor_linear_mask_propagation_constraints(smt)
            (['sbox_0_2_0_i',
              'sbox_0_2_1_i',
              ...
              'hw_sbox_0_2_2_o',
              'hw_sbox_0_2_3_o'],
             ['(assert (or sbox_0_2_0_i sbox_0_2_1_i sbox_0_2_2_i (not sbox_0_2_0_o) sbox_0_2_1_o))',
              '(assert (or sbox_0_2_2_i sbox_0_2_3_i sbox_0_2_0_o sbox_0_2_1_o (not sbox_0_2_3_o) hw_sbox_0_2_2_o))',
              ...
              '(assert (or (not hw_sbox_0_2_1_o)))',
              '(assert (or (not hw_sbox_0_2_0_o)))'])
        """
        input_bit_len, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        hw_bit_ids = [f'hw_{output_bit_ids[i]}' for i in range(input_bit_len)]
        sbox_values = self.description
        sboxes_lat_templates = model.sboxes_lat_templates

        # if optimized LAT template is not initialized in instance fields, compute it
        if f'{sbox_values}' not in sboxes_lat_templates:
            lat = SBox(sbox_values).linear_approximation_table()

            check_table_feasibility(lat, 'LAT', 'SMT')

            get_hamming_weight_function = (
                    lambda input_bit_len, entry: input_bit_len - int(math.log2(abs(entry))) - 1)
            template = smt_build_table_template(
                    lat, get_hamming_weight_function, input_bit_len, output_bit_len)
            sboxes_lat_templates[f'{sbox_values}'] = template

        bit_ids = input_bit_ids + output_bit_ids + hw_bit_ids
        template = sboxes_lat_templates[f'{sbox_values}']
        constraints = smt_get_sbox_probability_constraints(bit_ids, template)

        return bit_ids, constraints
