
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


class CipherOutput(Component):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, is_intermediate=False, output_tag=""):
        if is_intermediate:
            component_type = 'intermediate_output'
            description = [output_tag]
        else:
            component_type = 'cipher_output'
            description = ['cipher_output']
        component_id = f'{component_type}_{current_round_number}_{current_round_number_of_components}'
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)
        self._suffixes = ['_o']

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for OUTPUT in CMS CIPHER model.

        This method support OUTPUT operation using more than two operands.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: cipher_output_component = speck.component_from(2, 12)
            sage: cipher_output_component.cms_constraints()
            (['cipher_output_2_12_0',
              'cipher_output_2_12_1',
              'cipher_output_2_12_2',
              ...
              'xor_2_10_14 -cipher_output_2_12_30',
              'cipher_output_2_12_31 -xor_2_10_15',
              'xor_2_10_15 -cipher_output_2_12_31'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model):
        return self.cms_constraints()

    def cp_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for OUTPUT component.

        (both intermediate and cipher)

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: output_component = speck.component_from(2, 12)
            sage: output_component.cp_constraints()
            ([],
             ['constraint cipher_output_2_12[0] = xor_2_8[0];',
              'constraint cipher_output_2_12[1] = xor_2_8[1];',
             ...
              'constraint cipher_output_2_12[31] = xor_2_10[15];'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[i]};' for i in range(output_size)]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists declarations and constraints for OUTPUT component (both
        intermediate and cipher), for CP wordwise deterministic truncated xor
        differential.

        This is for the first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: output_component = aes.component_from(0, 35)
            sage: output_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)
            ([],
             ['constraint intermediate_output_0_35_value[0] = xor_0_31_value[0];',
               ...
              'constraint intermediate_output_0_35_active[15] = xor_0_34_active[3];'])
        """
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        all_inputs_active = []
        all_inputs_value = []
        cp_declarations = []
        for id_link, bit_positions in zip(input_id_link, input_bit_positions):
            all_inputs_active.extend([f'{id_link}_active[{bit_positions[j * model.word_size] // model.word_size}]'
                                      for j in range(len(bit_positions) // model.word_size)])
        for id_link, bit_positions in zip(input_id_link, input_bit_positions):
            all_inputs_value.extend([f'{id_link}_value[{bit_positions[j * model.word_size] // model.word_size}]'
                                     for j in range(len(bit_positions) // model.word_size)])
        cp_constraints = [f'constraint {output_id_link}_value[{i}] = {input_};'
                          for i, input_ in enumerate(all_inputs_value)]
        cp_constraints.extend([f'constraint {output_id_link}_active[{i}] = {input_};'
                               for i, input_ in enumerate(all_inputs_active)])

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        """
        Return lists declarations and constraints for OUTPUT component (both
        intermediate and cipher), for CP xor differential first step.

        This is for the first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: output_component = aes.component_from(0, 35)
            sage: output_component.cp_xor_differential_propagation_first_step_constraints(cp)
            (['array[0..15] of var 0..1: intermediate_output_0_35;'],
             ['constraint intermediate_output_0_35[0] = xor_0_31[0];',
             ...
              'constraint intermediate_output_0_35[15] = xor_0_34[3];'])
        """
        output_size = int(self.output_bit_size)
        input_id_links = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        all_inputs = []
        cp_constraints = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{bit_positions[j * model.word_size] // model.word_size}]'
                               for j in range(len(bit_positions) // model.word_size)])
        cp_declarations = [f'array[0..{(output_size - 1) // model.word_size}] of var 0..1: {output_id_link};']
        cp_constraints.extend([f'constraint {output_id_link}[{i}] = {input_};'
                               for i, input_ in enumerate(all_inputs)])
        result = cp_declarations, cp_constraints
        return result

    def cp_xor_differential_propagation_constraints(self, model):
        return self.cp_constraints()

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists declarations and constraints for OUTPUT component (both
        intermediate and cipher), for CP xor linear.

        This is for xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
            sage: output_component = speck.component_from(21, 12)
            sage: output_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..31] of var 0..1: cipher_output_21_12_i;',
              'array[0..31] of var 0..1: cipher_output_21_12_o;'],
             ['constraint cipher_output_21_12_o[0] = cipher_output_21_12_i[0];',
              'constraint cipher_output_21_12_o[1] = cipher_output_21_12_i[1];',
              ...
              'constraint cipher_output_21_12_o[30] = cipher_output_21_12_i[30];',
              'constraint cipher_output_21_12_o[31] = cipher_output_21_12_i[31];'])
        """
        id_ = self.id
        output_bit_size = self.output_bit_size
        cp_declarations = [f'array[0..{output_bit_size - 1}] of var 0..1: {id_}_i;',
                           f'array[0..{output_bit_size - 1}] of var 0..1: {id_}_o;']
        cp_constraints = [f'constraint {id_}_o[{i}] = {id_}_i[{i}];'
                          for i in range(output_bit_size)]

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        code = []
        cipher_output_params = [f'bit_vector_select_word({self.input_id_links[i]},  {self.input_bit_positions[i]})'
                         for i in range(len(self.input_id_links))]
        code.append(f'  {self.id} = bit_vector_CONCAT([{",".join(cipher_output_params)} ])')
        code.append(f'  if "{self.description[0]}" not in intermediateOutputs.keys():')
        code.append(f'      intermediateOutputs["{self.description[0]}"] = []')
        if convert_output_to_bytes:
            code.append(
                f'  intermediateOutputs["{self.description[0]}"]'
                f'.append(np.packbits({self.id}, axis=0).transpose())')
        else:
            code.append(
                f'  intermediateOutputs["{self.description[0]}"]'
                f'.append({self.id}.transpose())')
        return code

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = {params}[0]',
                f'  if "{self.description[0]}" not in intermediateOutputs.keys():',
                f'      intermediateOutputs["{self.description[0]}"] = []',
                f'  intermediateOutputs["{self.description[0]}"].append({self.id}.transpose())']

    def milp_constraints(self, model):
        """
        Return lists variables and constrains modeling a component of type
        OUTPUT (both intermediate and cipher), for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: output_component = simon.get_component_from_id("cipher_output_1_8")
            sage: variables, constraints = output_component.milp_constraints(milp)
            sage: variables
            [('x[xor_1_6_0]', x_0),
            ('x[xor_1_6_1]', x_1),
            ...
            ('x[cipher_output_1_8_30]', x_62),
            ('x[cipher_output_1_8_31]', x_63)]
            sage: constraints[0]
            x_32 == x_0
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        model.intermediate_output_names.append([self.id, output_bit_size])
        for i in range(output_bit_size):
            constraints.append(x[output_vars[i]] == x[input_vars[i]])

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints modeling a component of type
        Intermediate_output or Cipher_output for the bitwise deterministic truncated xor differential model.

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: output_component = simon.component_from(1,8)
            sage: variables, constraints = output_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[xor_1_6_0]', x_0),
            ('x_class[xor_1_6_1]', x_1),
            ...
            ('x_class[cipher_output_1_8_30]', x_62),
            ('x_class[cipher_output_1_8_31]', x_63)]
            sage: constraints
            [x_32 == x_0,
            ...
             x_63 == x_31]


        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        model.intermediate_output_names.append([self.id, output_bit_size])
        for i in range(output_bit_size):
            constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constrains modeling a component of type
        Intermediate_output or Cipher_output for the wordwise deterministic truncated xor differential model.

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: output_component = aes.component_from(1, 32)
            sage: variables, constraints = output_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[xor_1_31_word_0_class]', x_0),
             ('x_class[xor_1_31_word_1_class]', x_1),
             ...
             ('x[cipher_output_1_32_126]', x_286),
             ('x[cipher_output_1_32_127]', x_287)]
            sage: constraints
            [x_16 == x_0,
             x_17 == x_1,
             ...
             x_286 == x_158,
             x_287 == x_159]


        """
        x_class = model.trunc_wordvar

        input_vars, output_vars = self._get_wordwise_input_output_linked_class(model)
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        output_word_size = self.output_bit_size // model.word_size
        model.intermediate_output_names.append([self.id, output_word_size])
        for i in range(output_word_size):
            constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        bit_variables, bit_constraints = self.milp_constraints(model)

        return variables + bit_variables, constraints + bit_constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for OUTPUT component, for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: speck = speck.remove_key_schedule()
            sage: milp = MilpModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: output_component = speck.get_component_from_id("cipher_output_1_12")
            sage: variables, constraints = output_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[cipher_output_1_12_0_i]', x_0),
             ('x[cipher_output_1_12_1_i]', x_1),
             ('x[cipher_output_1_12_2_i]', x_2),
            ...
            ('x[cipher_output_1_12_30_o]', x_62),
            ('x[cipher_output_1_12_31_o]', x_63)]
            sage: constraints[0]
            x_32 == x_0
        """
        x = model.binary_variable
        constraints = []
        output_bit_size = self.output_bit_size
        model.intermediate_output_names.append([self.id, output_bit_size])
        ind_input_vars, ind_output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in ind_input_vars + ind_output_vars]
        constraints += [x[ind_output_vars[i]] == x[ind_input_vars[i]] for i in range(output_bit_size)]

        return variables, constraints

    def minizinc_constraints(self, model):
        """
        Return variables and constraints for the components with type OUTPUT
        (both intermediate and cipher), for MINIZINC CIPHER constraints.

        INPUT:

        - ``model`` -- **model object**; a model instance
        """

        var_names = self._define_var(model.input_postfix, model.output_postfix, model.data_type)
        intermediate_component_string = []
        component_id = self.id
        ninputs = self.input_bit_size
        input_vars = [f'{component_id}_{model.input_postfix}{i}' for i in range(ninputs)]
        output_vars = [f'{component_id}_{model.output_postfix}{i}' for i in range(ninputs)]

        for i in range(len(input_vars)):
            intermediate_component_string.append(f'constraint {input_vars[i]} = {output_vars[i]};')

        mzn_input_array = self._create_minizinc_1d_array_from_list(input_vars)
        if self.description[0] in ["round_output", "cipher_output", "round_key_output"]:
            model.mzn_output_directives.append("\noutput [\"component description: " + self.description[0] +
                                               ", id: " + component_id + "_input:\" ++ show(" + mzn_input_array +
                                               ")++\"\\n\"];" + "\n")

        model.intermediate_constraints_array.append({f'{component_id}_input': input_vars})

        return var_names, intermediate_component_string

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.minizinc_constraints(model)

    def minizinc_xor_differential_propagation_constraints(self, model):
        return self.minizinc_constraints(model)

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for OUTPUT in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: output_component = speck.component_from(2, 12)
            sage: output_component.sat_constraints()
            (['cipher_output_2_12_0',
              'cipher_output_2_12_1',
              'cipher_output_2_12_2',
              ...
              'xor_2_10_14 -cipher_output_2_12_30',
              'cipher_output_2_12_31 -xor_2_10_15',
              'xor_2_10_15 -cipher_output_2_12_31'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i]]))

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses for OUTPUT in SAT
        DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: output_component = speck.component_from(2, 12)
            sage: output_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            (['cipher_output_2_12_0_0',
              'cipher_output_2_12_1_0',
              'cipher_output_2_12_2_0',
              ...
              'xor_2_10_14_1 -cipher_output_2_12_30_1',
              'cipher_output_2_12_31_1 -xor_2_10_15_1',
              'xor_2_10_15_1 -cipher_output_2_12_31_1'])
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        _, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        constraints = []
        for out_id, in_id in zip(out_ids_0, in_ids_0):
            constraints.extend(sat_utils.cnf_equivalent([out_id, in_id]))
        for out_id, in_id in zip(out_ids_1, in_ids_1):
            constraints.extend(sat_utils.cnf_equivalent([out_id, in_id]))

        return out_ids_0 + out_ids_1, constraints

    def sat_xor_differential_propagation_constraints(self, model):
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for OUTPUT in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: output_component = speck.component_from(2, 12)
            sage: output_component.sat_xor_linear_mask_propagation_constraints()
            (['cipher_output_2_12_0_i',
              'cipher_output_2_12_1_i',
              'cipher_output_2_12_2_i',
              ...
              'cipher_output_2_12_30_o -cipher_output_2_12_30_i',
              'cipher_output_2_12_31_i -cipher_output_2_12_31_o',
              'cipher_output_2_12_31_o -cipher_output_2_12_31_i'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        constraints = []
        for input_bit_id, output_bit_id in zip(input_bit_ids, output_bit_ids):
            constraints.extend(sat_utils.cnf_equivalent([input_bit_id, output_bit_id]))
        result = input_bit_ids + output_bit_ids, constraints
        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing OUTPUT for SMT CIPHER constraints.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: output_component = speck.component_from(2, 12)
            sage: output_component.smt_constraints()
            (['cipher_output_2_12_0',
              'cipher_output_2_12_1',
              ...
              'cipher_output_2_12_30',
              'cipher_output_2_12_31'],
             ['(assert (= cipher_output_2_12_0 xor_2_8_0))',
              '(assert (= cipher_output_2_12_1 xor_2_8_1))',
              ...
              '(assert (= cipher_output_2_12_30 xor_2_10_14))',
              '(assert (= cipher_output_2_12_31 xor_2_10_15))'])
        """
        _, input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids[i]])
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model):
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for OUTPUT in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: output_component = speck.component_from(2, 12)
            sage: output_component.smt_xor_linear_mask_propagation_constraints()
            (['cipher_output_2_12_0_o',
              'cipher_output_2_12_1_o',
              ...
              'cipher_output_2_12_30_i',
              'cipher_output_2_12_31_i'],
             ['(assert (= cipher_output_2_12_0_i cipher_output_2_12_0_o))',
              '(assert (= cipher_output_2_12_1_i cipher_output_2_12_1_o))',
              ...
              '(assert (= cipher_output_2_12_30_i cipher_output_2_12_30_o))',
              '(assert (= cipher_output_2_12_31_i cipher_output_2_12_31_o))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        constraints = []
        for ids in zip(input_bit_ids, output_bit_ids):
            equation = smt_utils.smt_equivalent(ids)
            constraints.append(smt_utils.smt_assert(equation))
        result = output_bit_ids + input_bit_ids, constraints
        return result
