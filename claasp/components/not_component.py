
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


class NOT(Component):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size):
        component_id = f'not_{current_round_number}_{current_round_number_of_components}'
        component_type = 'word_operation'
        description = ['NOT', 0]
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for bitwise NOT.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: ascon = AsconPermutation(number_of_rounds=2)
            sage: algebraic = AlgebraicModel(ascon)
            sage: not_component = ascon.get_component_from_id("not_0_5")
            sage: not_component.algebraic_polynomials(algebraic)
            [not_0_5_y0 + not_0_5_x0 + 1,
             not_0_5_y1 + not_0_5_x1 + 1,
             not_0_5_y2 + not_0_5_x2 + 1,
            ...
             not_0_5_y61 + not_0_5_x61 + 1,
             not_0_5_y62 + not_0_5_x62 + 1,
             not_0_5_y63 + not_0_5_x63 + 1]
        """
        ninputs = self.input_bit_size
        noutputs = self.output_bit_size
        input_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        ring_R = model.ring()
        x = list(map(ring_R, input_vars))
        y = list(map(ring_R, output_vars))

        polynomials = [y[i] + x[i] + 1 for i in range(noutputs)]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for NOT operation in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.cms_constraints()
            (['not_0_8_0',
              'not_0_8_1',
              'not_0_8_2',
              ...
              '-not_0_8_30 -xor_0_6_30',
              'not_0_8_31 xor_0_6_31',
              '-not_0_8_31 -xor_0_6_31'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model):
        return self.sat_xor_differential_propagation_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model):
        return self.sat_xor_linear_mask_propagation_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for NOT component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.cp_constraints()
            ([],
             ['constraint not_0_8[0] = (xor_0_6[0] + 1) mod 2;',
             ...
              'constraint not_0_8[31] = (xor_0_6[31] + 1) mod 2;'])
        """
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = [f'constraint {output_id_link}[{i}] = ({input_} + 1) mod 2;'
                          for i, input_ in enumerate(all_inputs)]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_constraints(self):
        """
        Return lists of declarations and constraints for NOT for CP deterministic truncated xor differential model.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.cp_deterministic_truncated_xor_differential_constraints()
            ([],
             ['constraint not_0_8[0] = xor_0_6[0];',
             ...
              'constraint not_0_8[31] = xor_0_6[31];'])
        """
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = [f'constraint {output_id_link}[{i}] = {input_};'
                          for i, input_ in enumerate(all_inputs)]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists of declarations and constraints for NOT for CP deterministic truncated xor differential model.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: cp = CpModel(gift)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)
            ([],
             ['constraint not_0_8[0] = xor_0_6[0];',
              ...
             'constraint not_0_8[31] = xor_0_6[31];']) #doctest: +SKIP
        """
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        all_inputs_value = []
        all_inputs_active = []
        word_size = model.word_size
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs_value.extend([f'{id_link}_value[{bit_positions[j * word_size] // word_size}]'
                                     for j in range(len(bit_positions) // word_size)])
            all_inputs_active.extend([f'{id_link}_active[{bit_positions[j * word_size] // word_size}]'
                                      for j in range(len(bit_positions) // word_size)])
        input_len = len(all_inputs_value)
        cp_constraints = []
        for i in range(input_len):
            cp_constraints.append(f'constraint {output_id_link}_active[{i}] = {all_inputs_active[i]};')
            cp_constraints.append(f'if {all_inputs_value[i]} < 0 then {output_id_link}_value[{i}] = {all_inputs_value[i]} '\
                                  f'else {output_id_link}_value[{i}] = {2**word_size - 1} - {all_inputs_value[i]}')

        return cp_declarations, cp_constraints


    def cp_xor_differential_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for NOT component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: from claasp.components.not_component import NOT
            sage: aes = AESBlockCipher()
            sage: cp = CpModel(aes)
            sage: not_component = NOT(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'], [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7]], 32)
            sage: not_component.cp_xor_differential_first_step_constraints(cp)
            (['array[0..3] of var 0..1: not_0_18;'],
             ['constraint not_0_18[0] = sbox_0_2[0];',
              'constraint not_0_18[1] = sbox_0_6[0];',
              'constraint not_0_18[2] = sbox_0_10[0];',
              'constraint not_0_18[3] = sbox_0_14[0];'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        word_size = model.word_size
        cp_declarations = [f'array[0..{(output_size - 1) // model.word_size}] of var 0..1: {output_id_link};']
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{bit_positions[j * word_size] // word_size}]'
                               for j in range(len(bit_positions) // word_size)])
        cp_constraints = [f'constraint {output_id_link}[{i}] = {input_};'
                          for i, input_ in enumerate(all_inputs)]

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for NOT component for CP xor differential.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.cp_xor_differential_propagation_constraints()
            ([],
             ['constraint not_0_8[0] = xor_0_6[0];',
             ...
              'constraint not_0_8[31] = xor_0_6[31];'])
        """
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = [f'constraint {output_id_link}[{i}] = {input_};'
                          for i, input_ in enumerate(all_inputs)]
        result = cp_declarations, cp_constraints
        return result

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        return self.cp_xor_differential_first_step_constraints(model)

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for NOT component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: ascon = AsconPermutation(number_of_rounds=1)
            sage: not_component = ascon.component_from(0, 5)
            sage: not_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..63] of var 0..1:not_0_5_i;',
              'array[0..63] of var 0..1:not_0_5_o;'],
             ['constraint not_0_5_o[0]=not_0_5_i[0];',
              ...
              'constraint not_0_5_o[63]=not_0_5_i[63];'])
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        cp_declarations = []
        cp_constraints = []
        cp_declarations.append(f'array[0..{input_size - 1}] of var 0..1:{output_id_link}_i;')
        cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1:{output_id_link}_o;')
        for i in range(input_size):
            cp_constraints.append(f'constraint {output_id_link}_o[{i}]={output_id_link}_i[{i}];')
        result = cp_declarations, cp_constraints
        return result

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = bit_vector_NOT([{",".join(params)} ])']

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = byte_vector_NOT({params})']

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        input_size = self.input_bit_size
        input_int = int(solution['components_values'][f'{output_id_link}_i']['value'], 16)
        inputs = [int(digit) for digit in format(input_int, f'0{input_size}b')]
        component_sign = self.generic_sign_linear_constraints(inputs)
        sign = sign * component_sign
        solution['components_values'][f'{output_id_link}_o']['sign'] = component_sign
        solution['components_values'][output_id_link] = solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_o']
        del solution['components_values'][f'{output_id_link}_i']

        return sign

    def generic_sign_linear_constraints(self, inputs):
        """
        Return the constraints for finding the sign of an NOT component.

        INPUT:

        - ``inputs`` -- **list**; the input of the NOT component

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: from claasp.components.not_component import NOT
            sage: gift = GiftPermutation(number_of_rounds=1)
            sage: not_component = gift.component_from(0, 8)
            sage: inputs = [0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0]
            sage: not_component.generic_sign_linear_constraints(inputs)
            1
        """
        ones = 0
        for entry in inputs:
            if entry == 1:
                ones += 1
        parity = ones % 2
        if parity == 1:
            sign = -1
        else:
            sign = 1

        return sign

    def milp_constraints(self, model):
        """
        Return lists of variables and constraints for the NOT component for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: ascon = AsconPermutation()
            sage: milp = MilpModel(ascon)
            sage: milp.init_model_in_sage_milp_class()
            sage: not_component = ascon.component_from(0,5)
            sage: variables, constraints = not_component.milp_constraints(milp)
            sage: variables
            [('x[xor_0_2_0]', x_0),
            ('x[xor_0_2_1]', x_1),
            ...
            ('x[not_0_5_62]', x_126),
            ('x[not_0_5_63]', x_127)]
            sage: constraints
            [x_0 + x_64 == 1,
            x_1 + x_65 == 1,
            ...
            x_62 + x_126 == 1,
            x_63 + x_127 == 1]
        """
        x = model.binary_variable
        input_bit_size = self.input_bit_size
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        for i in range(input_bit_size):
            constraints.append(x[output_vars[i]] + x[input_vars[i]] == 1)

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for the NOT component for MILP xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: ascon = AsconPermutation()
            sage: milp = MilpModel(ascon)
            sage: milp.init_model_in_sage_milp_class()
            sage: not_component = ascon.component_from(0,5)
            sage: variables, constraints = not_component.milp_xor_differential_propagation_constraints(milp)
            sage: variables
            [('x[xor_0_2_0]', x_0),
            ('x[xor_0_2_1]', x_1),
            ...
             ('x[not_0_5_62]', x_126),
             ('x[not_0_5_63]', x_127)]
            sage: constraints
            [x_64 == x_0,
             x_65 == x_1,
            ...
             x_126 == x_62,
             x_127 == x_63]
        """
        x = model.binary_variable
        input_bit_size = self.input_bit_size
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        for i in range(input_bit_size):
            constraints.append(x[output_vars[i]] == x[input_vars[i]])
        result = variables, constraints
        return result

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for the NOT component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: ascon = AsconPermutation()
            sage: milp = MilpModel(ascon)
            sage: milp.init_model_in_sage_milp_class()
            sage: not_component = ascon.component_from(0,5)
            sage: variables, constraints = not_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[not_0_5_0_i]', x_0),
             ('x[not_0_5_1_i]', x_1),
            ...
             ('x[not_0_5_62_o]', x_126),
             ('x[not_0_5_63_o]', x_127)]
            sage: constraints
            [x_64 == x_0,
             x_65 == x_1,
            ...
             x_126 == x_62,
             x_127 == x_63]
        """
        x = model.binary_variable
        output_bit_size = self.output_bit_size
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        for i in range(output_bit_size):
            constraints.append(x[output_vars[i]] == x[input_vars[i]])
        result = variables, constraints
        return result

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for NOT component
        in deterministic truncated XOR differential model.

        INPUTS:

        - ``component`` -- *dict*, the NOT component in Graph Representation

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: cipher = GiftPermutation()
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: not_component = cipher.component_from(0,8)
            sage: variables, constraints = not_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[xor_0_6_0]', x_0),
             ('x_class[xor_0_6_1]', x_1),
             ...
             ('x_class[not_0_8_30]', x_62),
             ('x_class[not_0_8_31]', x_63)]
            sage: constraints
            [x_32 == x_0,
             x_33 == x_1,
             ...
             x_62 == x_30,
             x_63 == x_31]

        """
        x_class = model.trunc_binvar
        input_bit_size = self.input_bit_size
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []

        for i in range(input_bit_size):
            constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        return variables, constraints

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for NOT operation in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.sat_constraints()
            (['not_0_8_0',
              'not_0_8_1',
              'not_0_8_2',
              ...
              '-not_0_8_30 -xor_0_6_30',
              'not_0_8_31 xor_0_6_31',
              '-not_0_8_31 -xor_0_6_31'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_inequality(output_bit_ids[i], input_bit_ids[i]))

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses for NOT in SAT
        DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            (['not_0_8_0_0',
              'not_0_8_1_0',
              'not_0_8_2_0',
              ...
              'xor_0_6_30_0 -xor_0_6_30_1 -not_0_8_30_1',
              'xor_0_6_31_0 xor_0_6_31_1 not_0_8_31_1',
              'xor_0_6_31_0 -xor_0_6_31_1 -not_0_8_31_1'])
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        _, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        constraints = []
        for out_id, in_id in zip(out_ids_0, in_ids_0):
            constraints.extend(sat_utils.cnf_equivalent([out_id, in_id]))
        for out_id, in_id_0, in_id_1 in zip(out_ids_1, in_ids_0, in_ids_1):
            constraints.append(f'{in_id_0} {in_id_1} {out_id}')
            constraints.append(f'{in_id_0} -{in_id_1} -{out_id}')

        return out_ids_0 + out_ids_1, constraints

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for NOT operation in SAT xor differential.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.sat_xor_differential_propagation_constraints()
            (['not_0_8_0',
              'not_0_8_1',
              'not_0_8_2',
              ...
              'xor_0_6_30 -not_0_8_30',
              'not_0_8_31 -xor_0_6_31',
              'xor_0_6_31 -not_0_8_31'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i]]))
        result = output_bit_ids, constraints
        return result

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for NOT operation in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.gift_permutation import GiftPermutation
            sage: gift = GiftPermutation(number_of_rounds=3)
            sage: not_component = gift.component_from(0, 8)
            sage: not_component.sat_xor_linear_mask_propagation_constraints()
            (['not_0_8_0_i',
              'not_0_8_1_i',
              'not_0_8_2_i',
              ...
              'not_0_8_30_o -not_0_8_30_i',
              'not_0_8_31_i -not_0_8_31_o',
              'not_0_8_31_o -not_0_8_31_i'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([input_bit_ids[i], output_bit_ids[i]]))
        result = input_bit_ids + output_bit_ids, constraints
        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts for NOT operation for SMT CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: ascon = AsconPermutation(number_of_rounds=3)
            sage: not_component = ascon.component_from(0, 5)
            sage: not_component.smt_constraints()
            (['not_0_5_0',
              'not_0_5_1',
              ...
              'not_0_5_62',
              'not_0_5_63'],
             ['(assert (distinct not_0_5_0 xor_0_2_0))',
              '(assert (distinct not_0_5_1 xor_0_2_1))',
              ...
              '(assert (distinct not_0_5_62 xor_0_2_62))',
              '(assert (distinct not_0_5_63 xor_0_2_63))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_distinct(output_bit_ids[i], input_bit_ids[i])
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for NOT operation SMT xor differential.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: ascon = AsconPermutation(number_of_rounds=3)
            sage: not_component = ascon.component_from(0, 5)
            sage: not_component.smt_xor_differential_propagation_constraints()
            (['not_0_5_0',
              'not_0_5_1',
              ...
              'not_0_5_62',
              'not_0_5_63'],
             ['(assert (= not_0_5_0 xor_0_2_0))',
              '(assert (= not_0_5_1 xor_0_2_1))',
              ...
              '(assert (= not_0_5_62 xor_0_2_62))',
              '(assert (= not_0_5_63 xor_0_2_63))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids[i]])
            constraints.append(smt_utils.smt_assert(equation))
        result = output_bit_ids, constraints
        return result

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for NOT operation in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
            sage: ascon = AsconPermutation(number_of_rounds=3)
            sage: not_component = ascon.component_from(0, 5)
            sage: not_component.smt_xor_linear_mask_propagation_constraints()
            (['not_0_5_0_i',
              'not_0_5_1_i',
              ...
              'not_0_5_62_o',
              'not_0_5_63_o'],
             ['(assert (= not_0_5_0_i not_0_5_0_o))',
              '(assert (= not_0_5_1_i not_0_5_1_o))',
              ...
              '(assert (= not_0_5_62_i not_0_5_62_o))',
              '(assert (= not_0_5_63_i not_0_5_63_o))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        constraints = [smt_utils.smt_assert(smt_utils.smt_equivalent((input_bit_id, output_bit_id)))
                       for input_bit_id, output_bit_id in zip(input_bit_ids, output_bit_ids)]
        result = input_bit_ids + output_bit_ids, constraints
        return result
