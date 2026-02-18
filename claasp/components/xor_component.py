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


from claasp.input import Input
from claasp.component import Component
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.sat.utils import constants, utils as sat_utils
from claasp.cipher_modules.models.milp.utils import utils as milp_utils
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_xor_with_n_input_bits import (
    output_dictionary_that_contains_xor_inequalities,
    update_dictionary_that_contains_xor_inequalities_between_n_input_bits,
)
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import (
    update_dictionary_that_contains_wordwise_truncated_xor_inequalities_between_n_inputs,
    output_dictionary_that_contains_wordwise_truncated_xor_inequalities,
)
from claasp.cipher_modules.models.milp.utils.utils import espresso_pos_to_constraints
from claasp.name_mappings import WORD_OPERATION


def cp_build_truncated_table(numadd):
    """
    Return a model that generates the list of possible input/output couples for the given XOR component.

    INPUT:

    - ``numadd`` -- **integer**; the number of addenda

    EXAMPLES::

        sage: from claasp.components.xor_component import cp_build_truncated_table
        sage: cp_build_truncated_table(3)
        'array[0..4, 1..3] of int: xor_truncated_table_3 = array2d(0..4, 1..3, [0,0,0,0,1,1,1,0,1,1,1,0,1,1,1]);'
    """
    size = 2**numadd
    binary_list = (f"{i:0{numadd}b}" for i in range(size))
    table_items = [",".join(i) for i in binary_list if i.count("1") != 1]
    table = ",".join(table_items)
    xor_table = (
        f"array[0..{size - numadd - 1}, 1..{numadd}] of int: "
        f"xor_truncated_table_{numadd} = array2d(0..{size - numadd - 1}, 1..{numadd}, "
        f"[{table}]);"
    )

    return xor_table


def generic_with_constant_sign_linear_constraints(constant, const_mask, input_bit_positions):
    """
    Return the constraints for finding the sign of an XOR component.

    INPUT:

    - ``constant`` -- **list**; the value of the constant
    - ``const_mask`` -- **list**; the value of the mask applied to the constant
    - ``input_bit_positions`` -- **list**; the bit positions of the constant taken in input by the xor

    EXAMPLES::

        sage: from claasp.components.xor_component import generic_with_constant_sign_linear_constraints
        sage: constant = [0, 1, 1, 0, 0, 1, 1, 0]
        sage: const_mask = [0, 1, 0, 1, 1, 0, 0, 0]
        sage: input_bit_positions = [0,1,2,3,4,5,6,7]
        sage: generic_with_constant_sign_linear_constraints(constant, const_mask, input_bit_positions)
        -1
    """
    sign = +1
    sign_total = 0
    for i, bit in enumerate(const_mask):
        if bit == 1:
            sign_total += constant[input_bit_positions[i]]
    if (sign_total % 2) == 1:
        sign = -1

    return sign


def get_transformed_xor_input_links_and_positions(word_size, all_inputs, i, input_len, numadd, numb_of_inp):
    input_id_link = []
    input_bit_positions = [[] for _ in range(numb_of_inp + 1)]
    new_numb_of_inp = 0
    for j in range(numadd + 1):
        if all_inputs[i + input_len * j][0] not in input_id_link:
            input_id_link.append(all_inputs[i + input_len * j][0])
            input_bit_positions[new_numb_of_inp] += [
                all_inputs[i + input_len * j][1] * word_size + k for k in range(word_size)
            ]
            new_numb_of_inp += 1
        else:
            index = 0
            for c in range(len(input_id_link)):
                if input_id_link[c] == all_inputs[i + input_len * j][0]:
                    index += c
            input_bit_positions[index] += [all_inputs[i + input_len * j][1] * word_size + k for k in range(word_size)]
    input_bit_positions = [x for x in input_bit_positions if x != []]

    return input_bit_positions, input_id_link


def get_milp_constraints_from_inequalities(inequalities, input_vars, number_of_input_bits, output_vars, x):
    constraints = []
    for ineq in inequalities:
        for i in range(len(output_vars)):
            constraint = 0
            last_char = None
            for chunk in range(number_of_input_bits):
                char = ineq[chunk]
                if char == "1":
                    constraint += 1 - x[input_vars[i + chunk * len(output_vars)]]
                    last_char = ineq[number_of_input_bits]
                elif char == "0":
                    constraint += x[input_vars[i + chunk * len(output_vars)]]
                    last_char = ineq[number_of_input_bits]
            if last_char == "1":
                constraint += 1 - x[output_vars[i]]
                constraints.append(constraint >= 1)
            elif last_char == "0":
                constraint += x[output_vars[i]]
                constraints.append(constraint >= 1)

    return constraints


class XOR(Component):
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
    ):
        component_id = f"xor_{current_round_number}_{current_round_number_of_components}"
        component_type = WORD_OPERATION
        input_len = sum(map(len, input_bit_positions))
        description = ["XOR", int(input_len / output_bit_size)]
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return polynomials for Boolean XOR.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: xor_component = fancy.get_component_from_id("xor_0_7")
            sage: algebraic = AlgebraicModel(fancy)
            sage: xor_component.algebraic_polynomials(algebraic)
            [xor_0_7_y0 + xor_0_7_x12 + xor_0_7_x0,
             xor_0_7_y1 + xor_0_7_x13 + xor_0_7_x1,
             xor_0_7_y2 + xor_0_7_x14 + xor_0_7_x2,
             xor_0_7_y3 + xor_0_7_x15 + xor_0_7_x3,
             xor_0_7_y4 + xor_0_7_x16 + xor_0_7_x4,
             xor_0_7_y5 + xor_0_7_x17 + xor_0_7_x5,
             xor_0_7_y6 + xor_0_7_x18 + xor_0_7_x6,
             xor_0_7_y7 + xor_0_7_x19 + xor_0_7_x7,
             xor_0_7_y8 + xor_0_7_x20 + xor_0_7_x8,
             xor_0_7_y9 + xor_0_7_x21 + xor_0_7_x9,
             xor_0_7_y10 + xor_0_7_x22 + xor_0_7_x10,
             xor_0_7_y11 + xor_0_7_x23 + xor_0_7_x11]
        """
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        word_size = noutputs
        input_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]
        output_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]
        ring_R = model.ring()
        words_vars = [list(map(ring_R, input_vars))[i : i + word_size] for i in range(0, ninputs, word_size)]

        x = [ring_R.zero() for _ in range(noutputs)]
        for word_vars in words_vars:
            for i in range(noutputs):
                x[i] += word_vars[i]
        y = list(map(ring_R, output_vars))

        polynomials = [y[i] + x[i] for i in range(noutputs)]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for XOR operation in CMS CIPHER model.

        .. SEEALSO::

            :ref:`CMS CIPHER model  <cms-cipher-standard>` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: xor_component = speck.component_from(0,2)
            sage: xor_component.cms_constraints()
            (['xor_0_2_0',
              'xor_0_2_1',
              'xor_0_2_2',
              ...
              'x -xor_0_2_13 modadd_0_1_13 key_61',
              'x -xor_0_2_14 modadd_0_1_14 key_62',
              'x -xor_0_2_15 modadd_0_1_15 key_63'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            operands = [f"x -{output_bit_ids[i]}"]
            operands.extend(input_bit_ids[i::output_bit_len])
            constraints.append(" ".join(operands))

        return output_bit_ids, constraints

    def cms_xor_differential_propagation_constraints(self, model=None):
        return self.cms_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_xor_linear_mask_propagation_constraints(model)

    def cp_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for XOR component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.cp_constraints()
            ([],
             ['constraint xor_0_2[0] = (modadd_0_1[0] + key[48]) mod 2;',
              ...
              'constraint xor_0_2[15] = (modadd_0_1[15] + key[63]) mod 2;'])
        """
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_constraints = []
        for i in range(self.output_bit_size):
            operation = " + ".join(all_inputs[i::self.output_bit_size])
            cp_constraints.append(f"constraint {self.id}[{i}] = ({operation}) mod 2;")

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_constraints(self):
        r"""
        Return list declarations and constraints for XOR component CP deterministic truncated XOR differential model.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.cp_deterministic_truncated_xor_differential_constraints()
            ([],
             ['constraint if ((modadd_0_1[0] < 2) /\\ (key[48]< 2)) then xor_0_2[0] = (modadd_0_1[0] + key[48]) mod 2 else xor_0_2[0] = 2 endif;',
               ...
              'constraint if ((modadd_0_1[15] < 2) /\\ (key[63]< 2)) then xor_0_2[15] = (modadd_0_1[15] + key[63]) mod 2 else xor_0_2[15] = 2 endif;'])
        """
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_constraints = []
        for i in range(self.output_bit_size):
            operation = " < 2) /\\ (".join(all_inputs[i::self.output_bit_size])
            new_constraint = "constraint if (("
            new_constraint += operation + "< 2)) then "
            operation2 = " + ".join(all_inputs[i::self.output_bit_size])
            new_constraint += f"{self.id}[{i}] = ({operation2}) mod 2 else {self.id}[{i}] = 2 endif;"
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def cp_hybrid_deterministic_truncated_xor_differential_constraints(self):
        r"""
        Return list declarations and constraints for XOR component in the hybrid CP deterministic truncated
        XOR differential model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.cp_hybrid_deterministic_truncated_xor_differential_constraints()
            ([],
             ['constraint if (modadd_0_1[0] < 2) /\\ (key[48] < 2) then xor_0_2[0] = (modadd_0_1[0] + key[48]) mod 2 elseif (modadd_0_1[0] + key[48] = modadd_0_1[0]) then xor_0_2[0] = modadd_0_1[0] elseif (modadd_0_1[0] + key[48] = key[48]) then xor_0_2[0] = key[48] else xor_0_2[0] = 2 endif;',
               ...
              'constraint if (modadd_0_1[15] < 2) /\\ (key[63] < 2) then xor_0_2[15] = (modadd_0_1[15] + key[63]) mod 2 elseif (modadd_0_1[15] + key[63] = modadd_0_1[15]) then xor_0_2[15] = modadd_0_1[15] elseif (modadd_0_1[15] + key[63] = key[63]) then xor_0_2[15] = key[63] else xor_0_2[15] = 2 endif;'])
        """
        cp_declarations = []
        all_inputs = [
            f"{id_link}[{position}]"
            for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions)
            for position in bit_positions
        ]
        cp_constraints = []
        for i in range(self.output_bit_size):
            inputs = all_inputs[i::self.output_bit_size]
            condition = " < 2) /\\ (".join(inputs) + " < 2"
            operation_sum = " + ".join(inputs)
            new_constraint = (
                f"constraint if ({condition}) then {self.id}[{i}] = ({operation_sum}) mod 2 "
                f"elseif ({operation_sum} = {inputs[0]}) then {self.id}[{i}] = {inputs[0]} "
                f"elseif ({operation_sum} = {inputs[1]}) then {self.id}[{i}] = {inputs[1]} "
                f"else {self.id}[{i}] = 2 endif;"
            )
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        r"""
        Return lists declarations and constraints for XOR component CP wordwise deterministic truncated XOR differential model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: aes = AESBlockCipher(number_of_rounds=5)
            sage: cp = MznModel(aes)
            sage: xor_component = aes.component_from(0, 0)
            sage: xor_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)
            (['var -2..255: xor_0_0_temp_0_0_value;',
              ...
              'var 0..9: xor_0_0_bound_value_0_15 = if xor_0_0_temp_0_15_value + xor_0_0_temp_1_15_value > 0 then ceil(log2(xor_0_0_temp_0_15_value + xor_0_0_temp_1_15_value)) else 0 endif;'],
             ['constraint xor_0_0_temp_0_0_value = key_value[0] /\\ xor_0_0_temp_0_0_active = key_active[0];',
               ...
              'constraint if xor_0_0_temp_0_15_active + xor_0_0_temp_1_15_active > 2 then xor_0_0_active[15] == 3 /\\ xor_0_0_value[15] = -2 elseif xor_0_0_temp_0_15_active + xor_0_0_temp_1_15_active == 1 then xor_0_0_active[15] = 1 /\\ xor_0_0_value[15] = xor_0_0_temp_0_15_value + xor_0_0_temp_1_15_value elseif xor_0_0_temp_0_15_active + xor_0_0_temp_1_15_active == 0 then xor_0_0_active[15] = 0 /\\ xor_0_0_value[15] = 0 elseif xor_0_0_temp_0_15_value + xor_0_0_temp_1_15_value < 0 then xor_0_0_active[15] = 2 /\\ xor_0_0_value[15] = -1 elseif xor_0_0_temp_0_15_value == xor_0_0_temp_1_15_value then xor_0_0_active[15] = 0 /\\ xor_0_0_value[15] = 0 else xor_0_0_active[15] = 1 /\\ xor_0_0_value[15] = sum([(((floor(xor_0_0_temp_0_15_value/pow(2,j)) + floor(xor_0_0_temp_1_15_value/pow(2,j))) mod 2) * pow(2,j)) | j in 0..xor_0_0_bound_value_0_15]) endif;'])
        """
        output_id_link = self.id
        cp_declarations = []
        all_inputs_value = []
        all_inputs_active = []
        numadd = self.description[1]
        word_size = model.word_size
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs_value.extend(
                [
                    f"{id_link}_value[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
            all_inputs_active.extend(
                [
                    f"{id_link}_active[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
        input_len = len(all_inputs_value) // numadd
        cp_constraints = []
        initial_constraints = []
        for i in range(2 * numadd - 2):
            for j in range(input_len):
                cp_declarations.append(f"var -2..{2**word_size - 1}: {output_id_link}_temp_{i}_{j}_value;")
                cp_declarations.append(f"var 0..3: {output_id_link}_temp_{i}_{j}_active;")
        for i in range(input_len):
            for summand in range(numadd - 2):
                cp_declarations.append(
                    f"var 0..{word_size + 1}: {output_id_link}_bound_value_{numadd + summand - 1}_{i} = if {output_id_link}_temp_{numadd + summand - 1}_{i}_value "
                    f"+ {output_id_link}_temp_{summand}_{i}_value > 0 then ceil(log2({output_id_link}_temp_{numadd + summand - 1}_{i}_value "
                    f"+ {output_id_link}_temp_{summand}_{i}_value)) else 0 endif;"
                )
            cp_declarations.append(
                f"var 0..{word_size + 1}: {output_id_link}_bound_value_{numadd - 2}_{i} = if {output_id_link}_temp_{numadd - 2}_{i}_value "
                f"+ {output_id_link}_temp_{2 * numadd - 3}_{i}_value > 0 then ceil(log2({output_id_link}_temp_{numadd - 2}_{i}_value "
                f"+ {output_id_link}_temp_{2 * numadd - 3}_{i}_value)) else 0 endif;"
            )
        for i in range(numadd):
            for j in range(input_len):
                initial_constraints.append(
                    f"constraint {output_id_link}_temp_{i}_{j}_value = {all_inputs_value[i * input_len + j]} /\\ "
                    f"{output_id_link}_temp_{i}_{j}_active = {all_inputs_active[i * input_len + j]};"
                )
        cp_constraints += initial_constraints
        for i in range(input_len):
            new_constraint = ""
            for summand in range(numadd - 2):
                new_constraint += (
                    f"constraint if {output_id_link}_temp_{numadd + summand - 1}_{i}_active + {output_id_link}_temp_{summand}_{i}_active > 2 then "
                    f"{output_id_link}_temp_{numadd + summand}_{i}_active = 3 /\\ {output_id_link}_temp_{numadd + summand}_{i}_value = -2 "
                )
                new_constraint += (
                    f"elseif {output_id_link}_temp_{numadd + summand - 1}_{i}_active + {output_id_link}_temp_{summand}_{i}_active == 1 then"
                    f" {output_id_link}_temp_{numadd + summand}_{i}_active = 1 /\\ {output_id_link}_temp_{numadd + summand}_{i}_value ="
                    f" {output_id_link}_temp_{numadd + summand - 1}_{i}_value + {output_id_link}_temp_{summand}_{i}_value "
                )
                new_constraint += (
                    f"elseif {output_id_link}_temp_{numadd + summand - 1}_{i}_active + {output_id_link}_temp_{summand}_{i}_active == 0 then"
                    f" {output_id_link}_temp_{numadd + summand}_{i}_active = 0 /\\ {output_id_link}_temp_{numadd + summand}_{i}_value = 0 "
                )
                new_constraint += (
                    f"elseif {output_id_link}_temp_{numadd + summand - 1}_{i}_value + {output_id_link}_temp_{summand}_{i}_value < 0 then "
                    f"{output_id_link}_temp_{numadd + summand}_{i}_active = 2 /\\ {output_id_link}_temp_{numadd + summand}_{i}_value = -1 "
                )
                new_constraint += (
                    f"elseif {output_id_link}_temp_{numadd + summand - 1}_{i}_value == {output_id_link}_temp_{summand}_{i}_value then "
                    f"{output_id_link}_temp_{numadd + summand}_{i}_active = 0 /\\ {output_id_link}_temp_{numadd + summand}_{i}_value = 0 "
                )
                xor_to_int = (
                    f"sum([(((floor({output_id_link}_temp_{numadd + summand - 1}_{i}_value/pow(2,j)) + floor({output_id_link}_temp_{summand}_{i}"
                    f"_value/pow(2,j))) mod 2) * pow(2,j)) | j in 0..{output_id_link}_bound_value_{numadd + summand - 1}_{i}])"
                )
                new_constraint += (
                    f"else {output_id_link}_temp_{numadd + summand}_{i}_active = 1 /\\ {output_id_link}_temp_{numadd + summand}_{i}_value"
                    f" = {xor_to_int} endif;\n"
                )
            new_constraint += (
                f"constraint if {output_id_link}_temp_{numadd - 2}_{i}_active + {output_id_link}_temp_{2 * numadd - 3}_{i}_active > 2 then "
                f"{output_id_link}_active[{i}] == 3 /\\ {output_id_link}_value[{i}] = -2 "
            )
            new_constraint += (
                f"elseif {output_id_link}_temp_{numadd - 2}_{i}_active + {output_id_link}_temp_{2 * numadd - 3}_{i}_active == 1 then "
                f"{output_id_link}_active[{i}] = 1 /\\ {output_id_link}_value[{i}] = {output_id_link}_temp_{numadd - 2}_"
                f"{i}_value + {output_id_link}_temp_{2 * numadd - 3}_{i}_value "
            )
            new_constraint += (
                f"elseif {output_id_link}_temp_{numadd - 2}_{i}_active + {output_id_link}_temp_{2 * numadd - 3}_{i}_active == 0 then "
                f"{output_id_link}_active[{i}] = 0 /\\ {output_id_link}_value[{i}] = 0 "
            )
            new_constraint += (
                f"elseif {output_id_link}_temp_{numadd - 2}_{i}_value + {output_id_link}_temp_{2 * numadd - 3}_{i}_value < 0 then "
                f"{output_id_link}_active[{i}] = 2 /\\ {output_id_link}_value[{i}] = -1 "
            )
            new_constraint += (
                f"elseif {output_id_link}_temp_{numadd - 2}_{i}_value == {output_id_link}_temp_{2 * numadd - 3}_{i}_value then "
                f"{output_id_link}_active[{i}] = 0 /\\ {output_id_link}_value[{i}] = 0 "
            )
            xor_to_int = (
                f"sum([(((floor({output_id_link}_temp_{numadd - 2}_{i}_value/pow(2,j)) + floor({output_id_link}_temp_{2 * numadd - 3}_{i}"
                f"_value/pow(2,j))) mod 2) * pow(2,j)) | j in 0..{output_id_link}_bound_value_{numadd - 2}_{i}])"
            )
            new_constraint += (
                f"else {output_id_link}_active[{i}] = 1 /\\ {output_id_link}_value[{i}] = {xor_to_int} endif;"
            )
            cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model=None):
        return self.cp_constraints()

    def cp_xor_differential_propagation_first_step_constraints(self, model, variables_list=None):
        """
        Return lists of declarations and constraints for XOR component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model type
        - ``variables_list`` -- **list** (default: `None`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = MznModel(aes)
            sage: xor_component = aes.component_from(2, 31)
            sage: xor_component.cp_xor_differential_propagation_first_step_constraints(cp, cp._variables_list)
            (['array[0..1, 1..2] of int: xor_truncated_table_2 = array2d(0..1, 1..2, [0,0,1,1]);'],
             'constraint table([rot_2_16[0]]++[xor_2_26[0]], xor_truncated_table_2);')
        """
        numadd = self.description[1]
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend(
                [
                    f"{id_link}[{bit_positions[j * model.word_size] // model.word_size}]"
                    for j in range(len(bit_positions) // model.word_size)
                ]
            )
        input_len = len(all_inputs) // numadd
        cp_constraints = (
            "constraint table("
            + "++".join(f"[{all_inputs[input_len * j]}]" for j in range(numadd))
            + f", xor_truncated_table_{numadd});"
        )
        xor_table = cp_build_truncated_table(numadd)
        cp_declarations = []
        if xor_table not in variables_list:
            cp_declarations = [xor_table]

        return cp_declarations, cp_constraints

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for XOR component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..31] of var 0..1: xor_0_2_i;',
              'array[0..15] of var 0..1: xor_0_2_o;'],
             ['constraint xor_0_2_o[0] = xor_0_2_i[0];',
              ...
              'constraint xor_0_2_o[15] = xor_0_2_i[31];'])
        """
        cp_declarations = [
            f"array[0..{self.input_bit_size - 1}] of var 0..1: {self.id}_i;",
            f"array[0..{self.output_bit_size - 1}] of var 0..1: {self.id}_o;",
        ]
        num_of_addenda = self.description[1]
        input_len = self.input_bit_size // num_of_addenda
        cp_constraints = []
        for i in range(self.output_bit_size):
            cp_constraints.extend(
                [
                    f"constraint {self.id}_o[{i}] = {self.id}_i[{i + input_len * j}];"
                    for j in range(num_of_addenda)
                ]
            )
        result = cp_declarations, cp_constraints

        return result

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f"  {self.id} = bit_vector_XOR([{','.join(params)} ], {self.description[1]}, {self.output_bit_size})"]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_XOR({params})"]

    def get_word_operation_sign(self, constants, sign, solution):
        output_id_link = self.id
        for i, input_id_link in enumerate(self.input_id_links):
            if "constant" in input_id_link:
                int_const_mask = int(solution["components_values"][f"{input_id_link}_o"]["value"])
                bit_const_mask = [int(digit) for digit in format(int_const_mask, f"0{self.input_bit_size}b")]
                input_bit_positions = self.input_bit_positions[i]
                constant = int(constants[input_id_link])
                bit_constant = [int(digit) for digit in format(constant, f"0{self.input_bit_size}b")]
                component_sign = generic_with_constant_sign_linear_constraints(
                    bit_constant, bit_const_mask, input_bit_positions
                )
                sign = sign * component_sign
                solution["components_values"][f"{output_id_link}_o"]["sign"] = component_sign
        solution["components_values"][output_id_link] = solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_i"]

        return sign

    def milp_constraints(self, model):
        """
        Return a list of variables and a list of constrains modeling a component of type XOR for MILP CIPHER model.


        INPUT:

        - ``model`` -- **model object**; a model type

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: xor_component = simon.get_component_from_id("xor_0_5")
            sage: variables, constraints = xor_component.milp_constraints(milp)
            ...
            sage: variables
            [('x[and_0_4_0]', x_0),
            ('x[and_0_4_1]', x_1),
            ...
            ('x[xor_0_5_14]', x_46),
            ('x[xor_0_5_15]', x_47)]
            sage: constraints[:4]
            [x_32 <= x_0 + x_16,
             x_16 <= x_0 + x_32,
             x_0 <= x_16 + x_32,
             x_0 + x_16 + x_32 <= 2]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        number_of_input_bits = self.description[1]

        if number_of_input_bits == 2:
            for i in range(len(output_vars)):
                constraints.append(x[input_vars[i]] + x[input_vars[i + len(output_vars)]] >= x[output_vars[i]])
                constraints.append(x[output_vars[i]] + x[input_vars[i]] >= x[input_vars[i + len(output_vars)]])
                constraints.append(x[input_vars[i + len(output_vars)]] + x[output_vars[i]] >= x[input_vars[i]])
                constraints.append(x[input_vars[i]] + x[input_vars[i + len(output_vars)]] + x[output_vars[i]] <= 2)

            return variables, constraints

        update_dictionary_that_contains_xor_inequalities_between_n_input_bits(number_of_input_bits)
        dict_inequalities = output_dictionary_that_contains_xor_inequalities()
        inequalities = dict_inequalities[number_of_input_bits]
        constraints.extend(
            get_milp_constraints_from_inequalities(inequalities, input_vars, number_of_input_bits, output_vars, x)
        )

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_constraints(self, model):
        """
        Return a list of variables and a list of constraints for XOR operation in MILP XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: xor_component = simon.get_component_from_id("xor_0_5")
            sage: variables, constraints = xor_component.milp_xor_linear_constraints(milp)
            sage: variables
            [('x[xor_0_5_0_i]', x_0),
            ('x[xor_0_5_1_i]', x_1),
            ...
            ('x[xor_0_5_14_o]', x_46),
            ('x[xor_0_5_15_o]', x_47)]
            sage: constraints
            [x_32 == x_0,
            x_33 == x_1,
            x_34 == x_2,
            ...
            x_46 == x_30,
            x_47 == x_31]
        """
        x = model.binary_variable
        output_bit_size = self.output_bit_size
        ind_input_vars, ind_output_vars = self._get_independent_input_output_variables()
        input_vars, _ = self._get_input_output_variables()

        variables = [(f"x[{var}]", x[var]) for var in ind_input_vars + ind_output_vars]
        constraints = []
        number_of_inputs = self.description[1]

        for i in range(number_of_inputs):
            for j in range(output_bit_size):
                constraints.append(x[ind_output_vars[j]] == x[ind_input_vars[output_bit_size * i + j]])

        return variables, constraints

    def milp_xor_linear_mask_propagation_constraints(self, model):
        return self.milp_xor_linear_constraints(model)

    def milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for the XOR for two inputs
        in deterministic truncated XOR differential model.

        This method uses a binary encoding (where each variable v is seen as a binary tuple (v0, v1), where v0 is the MSB) to
        model the result c of the truncated XOR between inputs a and b.

        _______________
         a  |  b  |  c
        _______________
         0  |  0  |  0
         0  |  1  |  1
         0  |  2  |  2
         1  |  0  |  1
         1  |  1  |  0
         1  |  2  |  2
         2  |  0  |  2
         2  |  1  |  2
         2  |  2  |  2
        _______________

        Espresso was used to reduce the number of constraints to 10 inequalities.
        A k-input XOR is then split into k-1 2-input sequential XORs, for wich the results are stored in intermediate
        variables.

        INPUTS:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: cipher = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: xor_component = cipher.get_component_from_id("xor_0_5")
            sage: variables, constraints = xor_component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)
            sage: variables
            [('x[and_0_4_0_class_bit_0]', x_0),
             ('x[and_0_4_0_class_bit_1]', x_1),
             ...
             ('x[xor_0_5_15_class_bit_0]', x_94),
             ('x[xor_0_5_15_class_bit_1]', x_95)]
            sage: constraints
            [x_96 == 2*x_0 + x_1,
             x_97 == 2*x_2 + x_3,
             ...
             1 <= 1 - x_30 + x_94,
             1 <= 2 - x_62 - x_63]

        """

        x = model.binary_variable

        output_bit_size = self.output_bit_size
        input_id_tuples, output_id_tuples = self._get_input_output_variables_tuples()
        input_ids, output_ids = self._get_input_output_variables()

        variables = [
            (f"x[{var_elt}]", x[var_elt]) for var_tuple in input_id_tuples + output_id_tuples for var_elt in var_tuple
        ]

        linking_constraints = model.link_binary_tuples_to_integer_variables(
            input_id_tuples + output_id_tuples, input_ids + output_ids
        )
        number_of_inputs = self.description[1]
        constraints = [] + linking_constraints

        for i, output_id in enumerate(output_id_tuples):
            result_ids = [
                (f"temp_xor_{j}_{self.id}_{i}_0", f"temp_xor_{j}_{self.id}_{i}_1") for j in range(number_of_inputs - 2)
            ] + [output_id]
            constraints.extend(
                milp_utils.milp_xor_truncated(
                    model, input_id_tuples[i::output_bit_size][0], input_id_tuples[i::output_bit_size][1], result_ids[0]
                )
            )
            for chunk in range(1, number_of_inputs - 1):
                constraints.extend(
                    milp_utils.milp_xor_truncated(
                        model, input_id_tuples[i::output_bit_size][chunk + 1], result_ids[chunk - 1], result_ids[chunk]
                    )
                )

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for XOR component
        in deterministic truncated XOR differential model.

        INPUTS:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: cipher = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: xor_component = cipher.get_component_from_id("xor_0_5")
            sage: variables, constraints = xor_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[and_0_4_0]', x_0),
             ('x_class[and_0_4_1]', x_1),
            ...
             ('x_class[xor_0_5_14]', x_46),
             ('x_class[xor_0_5_15]', x_47)]
            sage: constraints
            [x_0 <= 3 - 2*x_48,
             2 - 2*x_48 <= x_0,
            ...
            x_47 <= 2 + 4*x_95,
            2 <= x_47 + 4*x_95]

        """

        x_class = model.trunc_binvar

        num_of_inputs = int(self.description[1])
        input_bit_size = int(self.input_bit_size / num_of_inputs)
        output_bit_size = self.output_bit_size
        input_vars, output_vars = self._get_input_output_variables()

        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]

        constraints = []

        # if a_i < 2 for all i then b = XOR(a_i, i in range(num_inputs))
        # else b = 2
        a = [
            [x_class[input_vars[i + chunk * input_bit_size]] for chunk in range(num_of_inputs)]
            for i in range(input_bit_size)
        ]
        b = [x_class[output_vars[i]] for i in range(output_bit_size)]

        for i in range(output_bit_size):
            list_ai_less_2 = []
            for chunk in range(num_of_inputs):
                # a < 2  iff a_less_2 = 1
                ai_less_2, constr = milp_utils.milp_less(model, a[i][chunk], 2, model._model.get_max(x_class))
                constraints.extend(constr)
                list_ai_less_2.append(ai_less_2)

            # ai_less_2 = 1 for all i  iff all_ai_less_2 = 1
            all_ai_less_2, constr = milp_utils.milp_generalized_and(model, list_ai_less_2)
            constraints.extend(constr)

            # if all_ai_less_2 == 1 then b = XOR(a_i, i in range(num_inputs))
            # else b = 2
            xor_constr = milp_utils.milp_generalized_xor(a[i], b[i])
            constr = milp_utils.milp_if_then_else(
                all_ai_less_2, xor_constr, [b[i] == 2], model._model.get_max(x_class) * num_of_inputs
            )
            constraints.extend(constr)

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for XOR component
        in deterministic truncated XOR differential model.

        This does not implement the XOR for more than 2 inputs in a sequential manner.
        Indeed, if Y = XOR(X_0, X_1, X_2), and the input patterns are:

        delta_X_0 = 1
        delta_X_1 = 2
        delta_X_2 = 1

        and X_0 = X_2, operating in a sequential way would yield delta_Y = 3.
        However, since X_0 and X_1 cancel each other out, it is possible to infer that delta_Y = 2.
        For this reason, we instead generate all valid combinations of input-output values D and use espresso to
        obtain a reduced set of inequalities modeling D.

        INPUTS:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: xor_component = cipher.get_component_from_id("xor_0_32")
            sage: variables, constraints = xor_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x[xor_0_31_word_0_class_bit_0]', x_0),
             ('x[xor_0_31_word_0_class_bit_1]', x_1),
            ...
             ('x[xor_0_32_30]', x_118),
             ('x[xor_0_32_31]', x_119)]
            sage: constraints
            [1 <= 1 + x_0 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 + x_8 + x_9 + x_41 - x_81,
             1 <= 1 + x_1 + x_40 + x_42 + x_43 + x_44 + x_45 + x_46 + x_47 + x_48 + x_49 - x_81,
             ...
             1 <= 1 + x_31 - x_39,
             1 <= 2 - x_30 - x_39]

        """
        if model.word_size == 8:
            return self.milp_wordwise_deterministic_truncated_xor_differential_sequential_constraints(model)

        x = model.binary_variable

        num_of_inputs = int(self.description[1])
        output_bit_size = self.output_bit_size
        output_word_size = output_bit_size // model.word_size

        input_vars, output_vars = self._get_wordwise_input_output_full_tuples(model)

        variables = [(f"x[{var}]", x[var]) for sublist in input_vars + output_vars for var in sublist]

        constraints = []
        update_dictionary_that_contains_wordwise_truncated_xor_inequalities_between_n_inputs(
            model.word_size, num_of_inputs
        )
        dict_inequalities = output_dictionary_that_contains_wordwise_truncated_xor_inequalities()
        inequalities = dict_inequalities[model.word_size][num_of_inputs]

        for i in range(output_word_size):
            all_vars = [x[_] for sublist in input_vars[i::output_word_size] + [output_vars[i]] for _ in sublist]
            minimized_constraints = espresso_pos_to_constraints(inequalities, all_vars)
            constraints.extend(minimized_constraints)

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_sequential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for XOR component
        in deterministic truncated XOR differential model.
        It should perform the wordwise xor for multiple inputs faster than the
        xor_wordwise_deterministic_truncated_xor_differential_constraints() methods but skips some cases
        e.g. if DX1 = 1, DX2 = 2, DX3 = 1 and X1 = X3, then DY = XOR(DX1, DX2, DX3) = 2 but this method will
        return 3

        INPUTS:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: xor_component = cipher.get_component_from_id("xor_0_31")
            sage: variables, constraints = xor_component.milp_wordwise_deterministic_truncated_xor_differential_sequential_constraints(milp)
            sage: variables
            [('x[sbox_0_26_word_0_class_bit_0]', x_0),
            ('x[sbox_0_26_word_0_class_bit_1]', x_1),
             ...
            ('x[xor_0_31_30]', x_158),
            ('x[xor_0_31_31]', x_159)]
            sage: constraints
            [1 <= 1 + x_0 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 + x_8 + x_9 + x_41 - x_161,
             1 <= 1 + x_1 + x_40 + x_42 + x_43 + x_44 + x_45 + x_46 + x_47 + x_48 + x_49 - x_161,
            ...
             1 <= 1 + x_111 - x_119,
             1 <= 2 - x_110 - x_119]


        """
        x = model.binary_variable

        number_of_inputs = int(self.description[1])
        output_word_size = self.output_bit_size // model.word_size

        input_vars, output_vars = self._get_wordwise_input_output_full_tuples(model)
        variables = [(f"x[{var}]", x[var]) for sublist in input_vars + output_vars for var in sublist]
        constraints = []

        for i, output_var in enumerate(output_vars):
            result_ids = [
                tuple(
                    [f"temp_xor_{j}_{self.id}_word_{i}_0", f"temp_xor_{j}_{self.id}_word_{i}_1"]
                    + [f"temp_xor_{j}_{self.id}_word_{i}_bit_{k}" for k in range(model.word_size)]
                )
                for j in range(number_of_inputs - 2)
            ] + [output_var]
            constraints.extend(
                milp_utils.milp_xor_truncated_wordwise(
                    model, input_vars[i::output_word_size][0], input_vars[i::output_word_size][1], result_ids[0]
                )
            )
            for chunk in range(1, number_of_inputs - 1):
                constraints.extend(
                    milp_utils.milp_xor_truncated_wordwise(
                        model, input_vars[i::output_word_size][chunk + 1], result_ids[chunk - 1], result_ids[chunk]
                    )
                )

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_simple_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for XOR component
        in deterministic truncated XOR differential model.

        It follows a simplified model:
        if dX0 + dX1 > 2
            then dY = 3
        elif dX0<2 / dX1<2
            then zeta Y = zetaX0 ^ zetaX1
        else dY = 2

        INPUTS:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: xor_component = cipher.get_component_from_id("xor_0_32")
            sage: variables, constraints = xor_component.milp_wordwise_deterministic_truncated_xor_differential_simple_constraints(milp)

        """
        x_class = model.trunc_wordvar

        num_of_inputs = int(self.description[1])
        output_bit_size = self.output_bit_size

        input_class_vars, output_class_vars = self._get_wordwise_input_output_linked_class(model)

        variables = [(f"x_class[{var}]", x_class[var]) for var in input_class_vars + output_class_vars]

        constraints = []

        input_vars = [x_class[var] for var in input_class_vars]
        output_vars = [x_class[var] for var in output_class_vars]

        for i in range(len(output_class_vars)):
            input_words = input_vars[i :: len(output_class_vars)]
            input_a = input_words[0]
            input_b = input_words[1]
            output_c = output_vars[i]
            var_if_list = []
            then_constraints_list = []

            # if dX0 + dX1 > 2 then dY = 3
            a_b_greater_2, geq_2_constraints = milp_utils.milp_geq(
                model, input_a + input_b, 2, 2 * model._model.get_max(x_class) + 1
            )
            var_if_list.append(a_b_greater_2)
            constraints.extend(geq_2_constraints)
            then_constraints_list.append([output_c == 3])

            # elif dX0 < 2 /\ dX1 < 2 then zeta Y = zetaX0 ^ zetaX1
            a_less_2, a_less_2_constraints = milp_utils.milp_less(model, input_a, 2, model._model.get_max(x_class) + 1)
            b_less_2, b_less_2_constraints = milp_utils.milp_less(model, input_a, 2, model._model.get_max(x_class) + 1)
            a_less_2_and_b_less_2, and_constraints = milp_utils.milp_and(model, a_less_2, b_less_2)

            constraints.extend(a_less_2_constraints + b_less_2_constraints + and_constraints)

            var_if_list.append(a_less_2_and_b_less_2)
            xor_constraints = []
            for _ in range(output_bit_size):
                xor_constraints.extend(milp_utils.milp_xor(input_a, input_b, output_c))
            then_constraints_list.append(xor_constraints)
            # else dY = 2
            else_constraints = [output_c == 2]

            constraints.extend(
                milp_utils.milp_if_elif_else(
                    model,
                    var_if_list,
                    then_constraints_list,
                    else_constraints,
                    num_of_inputs * model._model.get_max(x_class),
                )
            )

            return variables, constraints

    def minizinc_constraints(self, model):
        r"""
        Return variables and constraints for the XOR component for MINIZINC CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: minizinc = MznModel(speck)
            sage: xor_component = speck.get_component_from_id("xor_0_2")
            sage: _, xor_minizinc_constraints = xor_component.minizinc_constraints(minizinc)
            sage: xor_minizinc_constraints[0]
            'constraint xor_word(\narray1d(0..16-1, [xor_0_2_x16,xor_0_2_x17,xor_0_2_x18,xor_0_2_x19,xor_0_2_x20,xor_0_2_x21,xor_0_2_x22,xor_0_2_x23,xor_0_2_x24,xor_0_2_x25,xor_0_2_x26,xor_0_2_x27,xor_0_2_x28,xor_0_2_x29,xor_0_2_x30,xor_0_2_x31]),\narray1d(0..16-1, [xor_0_2_x0,xor_0_2_x1,xor_0_2_x2,xor_0_2_x3,xor_0_2_x4,xor_0_2_x5,xor_0_2_x6,xor_0_2_x7,xor_0_2_x8,xor_0_2_x9,xor_0_2_x10,xor_0_2_x11,xor_0_2_x12,xor_0_2_x13,xor_0_2_x14,xor_0_2_x15]),\narray1d(0..16-1, [xor_0_2_y0,xor_0_2_y1,xor_0_2_y2,xor_0_2_y3,xor_0_2_y4,xor_0_2_y5,xor_0_2_y6,xor_0_2_y7,xor_0_2_y8,xor_0_2_y9,xor_0_2_y10,xor_0_2_y11,xor_0_2_y12,xor_0_2_y13,xor_0_2_y14,xor_0_2_y15]))=true;\n'
        """

        def create_block_of_xor_constraints(input_vars_1_temp, input_vars_2_temp, output_varstrs_temp, i):
            mzn_input_array_1 = self._create_minizinc_1d_array_from_list(input_vars_1_temp)
            mzn_input_array_2 = self._create_minizinc_1d_array_from_list(input_vars_2_temp)
            mzn_output_array = self._create_minizinc_1d_array_from_list(output_varstrs_temp)
            if model.sat_or_milp == "sat":
                mzn_block_variables = ""
                mzn_block_constraints = (
                    f"constraint xor_word(\n{mzn_input_array_1},"
                    f"\n{mzn_input_array_2},\n{mzn_output_array})={model.true_value};\n"
                )
            else:
                mzn_block_variables = f"array [0..{noutputs}-1] of var 0..1: dummy_{component_id}_{i};\n"
                mzn_block_constraints = (
                    f"constraint xor_word(\n{mzn_input_array_1},\n{mzn_input_array_2},"
                    f"\n{mzn_output_array},\ndummy_{component_id}_{i})={model.true_value};\n"
                )
            return mzn_block_variables, mzn_block_constraints

        if self.description[0].lower() != "xor":
            raise ValueError("component must be Boolean XOR word_operation")

        var_names = self._define_var(model.input_postfix, model.output_postfix, model.data_type)

        mzn_constraints = []
        component_id = self.id
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        input_vars = [component_id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [component_id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        ninput_words = int(self.description[1])
        word_chunk = noutputs
        new_output_vars = [input_vars[0 * word_chunk : 0 * word_chunk + word_chunk]]
        for i in range(ninput_words - 2):
            new_output_vars_temp = []
            for output_var in output_vars:
                mzn_constraints += [f"var {model.data_type}: {output_var}_{str(i)};\n"]
                new_output_vars_temp.append(output_var + "_" + str(i))
            new_output_vars.append(new_output_vars_temp)

        for i in range(1, ninput_words):
            input_vars_1 = input_vars[i * word_chunk : i * word_chunk + word_chunk]
            input_vars_2 = new_output_vars[i - 1]
            if i == ninput_words - 1:
                mzn_variables_and_constraints = create_block_of_xor_constraints(
                    input_vars_1, input_vars_2, output_vars, i
                )
            else:
                mzn_variables_and_constraints = create_block_of_xor_constraints(
                    input_vars_1, input_vars_2, new_output_vars[i], i
                )

            var_names += [mzn_variables_and_constraints[0]]
            mzn_constraints += [mzn_variables_and_constraints[1]]

        return var_names, mzn_constraints

    def minizinc_xor_differential_propagation_constraints(self, model):
        return self.minizinc_constraints(model)

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing XOR for SAT CIPHER model

        This method translates in CNF the constraint ``z = Xor(x, y)``. In prefixed notation, it becomes:
        ``And(Or(z, Not(x), y), Or(z, x, Not(y)), Or(z, Not(x), Not(y)), Or(z, x, y))``.
        This method supports XOR operation using more than two operands.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.sat_constraints()
            (['xor_0_2_0',
              'xor_0_2_1',
              ...
              'xor_0_2_14',
              'xor_0_2_15'],
             ['-xor_0_2_0 modadd_0_1_0 key_48',
              'xor_0_2_0 -modadd_0_1_0 key_48',
              ...
              'xor_0_2_15 modadd_0_1_15 -key_63',
              '-xor_0_2_15 -modadd_0_1_15 -key_63'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            result_bit_ids = [f"inter_{j}_{output_bit_ids[i]}" for j in range(self.description[1] - 2)] + [
                output_bit_ids[i]
            ]
            constraints.extend(sat_utils.cnf_xor_seq(result_bit_ids, input_bit_ids[i::output_bit_len]))

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses representing XOR for SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model

        .. SEEALSO::

            - :ref:`sat-standard` for the format.
            - :obj:`sat_constraints() <components.xor_component.XOR.sat_constraints>` for the model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            (['xor_0_2_0_0',
              'xor_0_2_1_0',
              ...
              'xor_0_2_14_1',
              'xor_0_2_15_1'],
             ['xor_0_2_0_0 -modadd_0_1_0_0',
              'xor_0_2_0_0 -key_48_0',
              ...
              'key_63_1 xor_0_2_15_0 xor_0_2_15_1 -modadd_0_1_15_1',
              'xor_0_2_15_0 -modadd_0_1_15_1 -key_63_1 -xor_0_2_15_1'])
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        out_len, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        in_ids = [(id_0, id_1) for id_0, id_1 in zip(in_ids_0, in_ids_1)]
        out_ids = [(id_0, id_1) for id_0, id_1 in zip(out_ids_0, out_ids_1)]
        constraints = []
        for i, out_id in enumerate(out_ids):
            result_ids = [
                (f"inter_{j}_{self.id}_{i}_0", f"inter_{j}_{self.id}_{i}_1") for j in range(self.description[1] - 2)
            ] + [out_id]
            constraints.extend(sat_utils.cnf_xor_truncated_seq(result_ids, in_ids[i::out_len]))

        return out_ids_0 + out_ids_1, constraints

    def sat_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing XOR for SAT XOR DIFFERENTIAL model

        .. SEEALSO::

            - :ref:`sat-standard` for the format.
            - :obj:`sat_constraints() <components.xor_component.XOR.sat_constraints>` for the model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.sat_xor_differential_propagation_constraints()
            (['xor_0_2_0',
              'xor_0_2_1',
              ...
              'xor_0_2_14',
              'xor_0_2_15'],
             ['-xor_0_2_0 modadd_0_1_0 key_48',
              'xor_0_2_0 -modadd_0_1_0 key_48',
              ...
              'xor_0_2_15 modadd_0_1_15 -key_63',
              '-xor_0_2_15 -modadd_0_1_15 -key_63'])
        """
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing XOR for SAT XOR LINEAR model

        .. SEEALSO::

            :ref:`sat-standard` for the format, [LWR2016]_ for the algorithm.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.sat_xor_linear_mask_propagation_constraints()
            (['xor_0_2_0_i',
              'xor_0_2_1_i',
              ...
              'xor_0_2_14_o',
              'xor_0_2_15_o'],
             ['xor_0_2_0_i -xor_0_2_0_o',
              'xor_0_2_16_i -xor_0_2_0_i',
              ...
              'xor_0_2_31_i -xor_0_2_15_i',
              'xor_0_2_15_o -xor_0_2_31_i'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        bit_ids = input_bit_ids + output_bit_ids
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent(bit_ids[i::output_bit_len]))
        result = bit_ids, constraints

        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing XOR for SMT CIPHER model

        Since the XOR operation is part of the SMT-LIB formalism, the operation can be modeled using the corresponding
        builtin operation, e.g. ``z = XOR(x, y)`` becomes ``(assert (= z (xor x y)))``.
        This method support XOR operation using more than two inputs.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.smt_constraints()
            (['xor_0_2_0',
              'xor_0_2_1',
              ...
              'xor_0_2_14',
              'xor_0_2_15'],
             ['(assert (= xor_0_2_0 (xor modadd_0_1_0 key_48)))',
              '(assert (= xor_0_2_1 (xor modadd_0_1_1 key_49)))',
              ...
              '(assert (= xor_0_2_14 (xor modadd_0_1_14 key_62)))',
              '(assert (= xor_0_2_15 (xor modadd_0_1_15 key_63)))'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            operation = smt_utils.smt_xor(input_bit_ids[i::output_bit_len])
            equation = smt_utils.smt_equivalent([output_bit_ids[i], operation])
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing XOR for SMT XOR DIFFERENTIAL model

        .. SEEALSO::

            :obj:`smt_constraints() <components.xor_component.XOR.sat_constraints>` for the model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.smt_xor_differential_propagation_constraints()
            (['xor_0_2_0',
              'xor_0_2_1',
              ...
              'xor_0_2_14',
              'xor_0_2_15'],
             ['(assert (= xor_0_2_0 (xor modadd_0_1_0 key_48)))',
              '(assert (= xor_0_2_1 (xor modadd_0_1_1 key_49)))',
              ...
              '(assert (= xor_0_2_14 (xor modadd_0_1_14 key_62)))',
              '(assert (= xor_0_2_15 (xor modadd_0_1_15 key_63)))'])
        """
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing XOR for SMT XOR LINEAR model

        .. SEEALSO::

            [LWR2016]_ for the algorithm.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: xor_component = speck.component_from(0, 2)
            sage: xor_component.smt_xor_linear_mask_propagation_constraints()
            (['xor_0_2_0_o',
              'xor_0_2_1_o',
              ...
              'xor_0_2_30_i',
              'xor_0_2_31_i'],
             ['(assert (= xor_0_2_0_o xor_0_2_0_i xor_0_2_16_i))',
              '(assert (= xor_0_2_1_o xor_0_2_1_i xor_0_2_17_i))',
              ...
              '(assert (= xor_0_2_14_o xor_0_2_14_i xor_0_2_30_i))',
              '(assert (= xor_0_2_15_o xor_0_2_15_i xor_0_2_31_i))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        bit_ids = output_bit_ids + input_bit_ids
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent(bit_ids[i::output_bit_len])
            constraints.append(smt_utils.smt_assert(equation))
        result = bit_ids, constraints

        return result

    def cp_transform_xor_components_for_first_step(self, model):
        """
        Transform a XOR component into components involving only one byte for CP.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = MznModel(aes)
            sage: xor_component = aes.component_from(0, 31)
            sage: xor_component.cp_transform_xor_components_for_first_step(cp)
            (['array[0..3] of var 0..1: xor_0_31;'], [])
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        numadd = self.description[1]
        numb_of_inp = len(input_id_link)
        all_inputs = []
        cp_declarations = [f"array[0..{(output_size - 1) // model.word_size}] of var 0..1: {output_id_link};"]
        number_of_mix = 0
        is_mix = False
        for i in range(numb_of_inp):
            for j in range(len(input_bit_positions[i]) // model.word_size):
                all_inputs.append([input_id_link[i], input_bit_positions[i][j * model.word_size] // model.word_size])
            rem = len(input_bit_positions[i]) % model.word_size
            if rem != 0:
                rem = model.word_size - (len(input_bit_positions[i]) % model.word_size)
                all_inputs.append([f"{output_id_link}_i", number_of_mix])
                number_of_mix += 1
                is_mix = True
                l = 1
                while rem > 0:
                    length = len(input_bit_positions[i + l])
                    del input_bit_positions[i + l][0:rem]
                    rem -= length
                    l += 1
        if is_mix:
            cp_declarations.append(f"array[0..{number_of_mix - 1}] of var 0..1: {output_id_link}_i;")
        all_inputs += [[output_id_link, i] for i in range(output_size // model.word_size)]
        input_len = output_size // model.word_size
        for i in range(input_len):
            input_bit_positions, input_id_link = get_transformed_xor_input_links_and_positions(
                model.word_size, all_inputs, i, input_len, numadd, numb_of_inp
            )
            input_bits = 0
            for input_bit in input_bit_positions:
                input_bits += len(input_bit)
            xor_component = XOR("", "", input_id_link, input_bit_positions, input_bits)
            xor_component.set_description(["XOR", numadd + 1])
            model.list_of_xor_components.append(xor_component)
        cp_constraints = []

        return cp_declarations, cp_constraints
