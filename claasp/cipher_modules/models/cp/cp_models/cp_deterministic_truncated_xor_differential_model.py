
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


from claasp.cipher_modules.models.cp.cp_model import CpModel, solve_satisfy
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL)


class CpDeterministicTruncatedXorDifferentialModel(CpModel):

    def __init__(self, cipher):
        super().__init__(cipher)

    def build_deterministic_truncated_xor_differential_trail_model(self, fixed_variables=[], number_of_rounds=None):
        """
        Build the CP model for the search of deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: cp.build_deterministic_truncated_xor_differential_trail_model(fixed_variables)
        """
        self.initialise_model()
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        deterministic_truncated_xor_differential = constraints

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                               SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'OR', 'MODADD', 'MODSUB', 'NOT', 'ROTATE', 'SHIFT', 'XOR']
            if component.type not in component_types or \
                    (component.type == WORD_OPERATION and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            variables, constraints = component.cp_deterministic_truncated_xor_differential_trail_constraints()
            self._variables_list.extend(variables)
            deterministic_truncated_xor_differential.extend(constraints)

        variables, constraints = self.input_deterministic_truncated_xor_differential_constraints(number_of_rounds)
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        deterministic_truncated_xor_differential.extend(
            self.final_deterministic_truncated_xor_differential_constraints())
        self._model_constraints = self._model_prefix + self._variables_list + deterministic_truncated_xor_differential

    def build_inverse_deterministic_truncated_xor_differential_trail_model(self, number_of_rounds, fixed_variables=[]):
        """
        Build CP model for search of deterministic truncated XOR differential trails for the inverted cipher.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `[]`); number of rounds
        - ``fixed_variables`` -- **list**; dictionaries containing the variables to be fixed in standard format

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: cp.build_inverse_deterministic_truncated_xor_differential_trail_model(2, fixed_variables)
        """
        self._model_prefix = []
        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        self._model_constraints = constraints
        cipher = self._cipher

        for cipher_round in range(number_of_rounds + 1):
            for component in cipher.get_all_components():
                component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                                   SBOX, MIX_COLUMN, WORD_OPERATION]
                operation = component.description[0]
                operation_types = ['AND', 'OR', 'MODADD', 'MODSUB', 'NOT', 'ROTATE', 'SHIFT', 'XOR']
                variables, constraints = \
                    component.cp_deterministic_truncated_xor_differential_trail_constraints()
                if component.type not in component_types or \
                        (component.type == WORD_OPERATION and operation not in operation_types):
                    print(f'{component.id} not yet implemented')
                elif INTERMEDIATE_OUTPUT in component.type or CIPHER_OUTPUT in component.type:
                    if cipher_round == number_of_rounds:
                        variables, constraints = self.output_inverse_constraints(component)
                    else:
                        variables, constraints = self.output_constraints(component)
                self._variables_list.extend(variables)
                self._model_constraints.extend(constraints)

        variables, constraints = self.input_deterministic_truncated_xor_differential_constraints(number_of_rounds, True)
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        self._model_constraints.extend(
            self.final_impossible_constraints(number_of_rounds))

    def final_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: cp.final_deterministic_truncated_xor_differential_constraints()[:-1]
            ['solve satisfy;']
        """
        cipher_inputs = self._cipher.inputs
        cipher = self._cipher
        cp_constraints = [solve_satisfy]
        new_constraint = 'output['
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for component_id in cipher.get_all_components_ids():
            new_constraint = new_constraint + \
                f'\"{component_id} = \"++ show({component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(new_constraint)

        return cp_constraints

    def final_impossible_constraints(self, number_of_rounds):
        """
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - ``number_of_rounds`` -- **integer**; number of rounds

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: cp.final_impossible_constraints(2)[:-2]
            ['solve satisfy;']
        """
        cipher_inputs = self._cipher.inputs
        cipher = self._cipher
        cp_constraints = [solve_satisfy]
        new_constraint = 'output['
        incompatibility_constraint = 'constraint'
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for cipher_round in range(self._cipher.number_of_rounds):
            for component in cipher.get_components_in_round(cipher_round):
                component_id = component.id
                if 'output' in component.type and cipher_round == number_of_rounds - 1:
                    output_bit_size = component.output_bit_size
                    new_constraint = new_constraint + \
                        f'\"{component_id} = \"++ show({component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    new_constraint = new_constraint + \
                        f'\"{component_id}_inverse = \"++ show({component_id}_inverse)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    for i in range(output_bit_size):
                        incompatibility_constraint += f'({component_id}[{i}]+{component_id}_inverse[{i}]=1) \\/ '
                else:
                    new_constraint = new_constraint + \
                        f'\"{component_id}_inverse = \"++ show({component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        incompatibility_constraint = incompatibility_constraint[:-4] + ';'
        new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(incompatibility_constraint)
        cp_constraints.append(new_constraint)

        return cp_constraints

    def find_all_deterministic_truncated_xor_differential_trail(self, number_of_rounds,
                                                                fixed_values=[], solver_name=None):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``number_of_rounds`` -- **integer**; number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `None`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=[0]*32)
            sage: key = set_fixed_variables(
            ....:         component_id='key',
            ....:         constraint_type='equal',
            ....:         bit_positions=range(64),
            ....:         bit_values=[0]*64)
            sage: cp.find_all_deterministic_truncated_xor_differential_trail(3, [plaintext,key], 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r3',
              'components_values': {'cipher_output_2_12': {'value': '22222222222222202222222222222222',
                'weight': 0},
              ...
              'memory_megabytes': 0.02,
              'model_type': 'deterministic_truncated_xor_differential',
              'solver_name': 'Chuffed',
              'solving_time_seconds': 0.002,
              'total_weight': '0.0'}]
        """
        self.build_deterministic_truncated_xor_differential_trail_model(fixed_values, number_of_rounds)

        return self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name)

    def find_one_deterministic_truncated_xor_differential_trail(self, number_of_rounds=None,
                                                                fixed_values=[], solver_name=None):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=[0]*32)
            sage: key = set_fixed_variables(
            ....:         component_id='key',
            ....:         constraint_type='equal',
            ....:         bit_positions=range(64),
            ....:         bit_values=[0]*64)
            sage: cp.find_one_deterministic_truncated_xor_differential_trail(1, [plaintext,key], 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r1',
              'components_values': {'cipher_output_0_6': {'value': '22222222222222212222222222222220',
                'weight': 0},
               'intermediate_output_0_5': {'value': '0000000000000000', 'weight': 0},
               'key': {'value': '0000000000000000000000000000000000000000000000000000000000000000',
                'weight': 0},
               'modadd_0_1': {'value': '2222222222222221', 'weight': 0},
               'plaintext': {'value': '11111111011111111111111111111111', 'weight': 0},
               'rot_0_0': {'value': '1111111111111110', 'weight': 0},
               'rot_0_3': {'value': '1111111111111111', 'weight': 0},
               'xor_0_2': {'value': '2222222222222221', 'weight': 0},
               'xor_0_4': {'value': '2222222222222220', 'weight': 0}},
              'memory_megabytes': 0.01,
              'model_type': 'deterministic_truncated_xor_differential_one_solution',
              'solver_name': 'Chuffed',
              'solving_time_seconds': 0.0,
              'total_weight': '0.0'}]
        """
        self.build_deterministic_truncated_xor_differential_trail_model(fixed_values, number_of_rounds)

        return self.solve('deterministic_truncated_xor_differential_one_solution', solver_name)

    def input_deterministic_truncated_xor_differential_constraints(self, number_of_rounds, inverse=False):
        """
        Return a list of CP constraints for the inputs of the cipher for the first step model.

        INPUT:

        - ``number_of_rounds`` -- **integer**; number of rounds
        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: aes = AESBlockCipher()
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(aes)
            sage: cp.input_deterministic_truncated_xor_differential_constraints(10)
            (['array[0..127] of var 0..2: key;',
              'array[0..127] of var 0..2: plaintext;',
               ...
              'constraint count(plaintext,2) = 0;'])
        """
        cp_constraints = []
        cp_declarations = [f'array[0..{bit_size - 1}] of var 0..2: {input_};'
                           for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)]
        cipher = self._cipher
        rounds = self._cipher.number_of_rounds - number_of_rounds if inverse else number_of_rounds
        for component in cipher.get_all_components():
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type \
                    and inverse and cipher.get_round_from_component_id(component.id) == rounds - 1:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link}_inverse;')
            elif CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
                cp_constraints.append(f'constraint count({output_id_link},2) < {output_size};')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
        if inverse:
            for i, input in enumerate(self._cipher.inputs):
                if CIPHER_OUTPUT in input:
                    cp_constraints.append(f'constraint count({input},1) > 0;')
                    cp_constraints.append(f'constraint count({input},2) = 0;')
        else:
            cp_constraints.append('constraint count(plaintext,1) > 0;')
            cp_constraints.append('constraint count(plaintext,2) = 0;')

        return cp_declarations, cp_constraints

    def input_wordwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of CP constraints for the inputs of the cipher for truncated deterministic xor differential model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: aes = AESBlockCipher(number_of_rounds = 2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(aes)
            sage: cp.input_wordwise_deterministic_truncated_xor_differential_constraints()
            (['array[0..15] of var 0..3: key_active;',
              'array[0..15] of var -2..255: key_value;',
               ...
              'array[0..15] of var -2..255: cipher_output_1_32_value;'],
             ['constraint if key_active[0] == 0 then key_value[0] = 0 elseif key_active[0] == 1 then key_value[0] > 0 elseif key_active[0] == 2 then key_value[0] =-1 else key_value[0] =-2 endif;',
               ...
              'constraint if cipher_output_1_32_active[15] == 0 then cipher_output_1_32_value[15] = 0 elseif cipher_output_1_32_active[15] == 1 then cipher_output_1_32_value[15] > 0 elseif cipher_output_1_32_active[15] == 2 then cipher_output_1_32_value[15] =-1 else cipher_output_1_32_value[15] =-2 endif;',
              'constraint count(cipher_output_1_32_active,2) < 128;',
              'constraint count(plaintext,1) > 0;',
              'constraint count(plaintext,2) = 0;'])
        """
        cp_constraints = []
        cp_declarations = []
        for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            cp_declarations.append(f'array[0..{bit_size // self.word_size - 1}] of var 0..3: {input_}_active;')
            cp_declarations.append(
                f'array[0..{bit_size // self.word_size - 1}] of var -2..{2 ** self.word_size - 1}: {input_}_value;')
            for i in range(bit_size // self.word_size):
                cp_constraints.append(f'constraint if {input_}_active[{i}] == 0 then {input_}_value[{i}] = 0 elseif '
                                      f'{input_}_active[{i}] == 1 then {input_}_value[{i}] > 0 elseif '
                                      f'{input_}_active[{i}] == 2 then {input_}_value[{i}] =-1 else '
                                      f'{input_}_value[{i}] =-2 endif;')
        for component in self._cipher.get_all_components():
            if CONSTANT not in component.type:
                output_id_link = component.id
                output_size = int(component.output_bit_size)
                cp_declarations.append(
                    f'array[0..{output_size // self.word_size - 1}] of var 0..3: {output_id_link}_active;')
                cp_declarations.append(
                    f'array[0..{output_size // self.word_size - 1}] of var -2..{2 ** self.word_size - 1}: '
                    f'{output_id_link}_value;')
                for i in range(output_size // self.word_size):
                    cp_constraints.append(
                        f'constraint if {output_id_link}_active[{i}] == 0 then {output_id_link}_value[{i}] = 0 elseif '
                        f'{output_id_link}_active[{i}] == 1 then {output_id_link}_value[{i}] > 0 elseif '
                        f'{output_id_link}_active[{i}] == 2 then {output_id_link}_value[{i}] =-1 else '
                        f'{output_id_link}_value[{i}] =-2 endif;')
                if CIPHER_OUTPUT in component.type:
                    cp_constraints.append(f'constraint count({output_id_link}_active,2) < {output_size};')
        cp_constraints.append('constraint count(plaintext,1) > 0;')
        cp_constraints.append('constraint count(plaintext,2) = 0;')

        return cp_declarations, cp_constraints

    def output_constraints(self, component):
        """
        Return lists of declarations and constraints for CP output component (both intermediate and cipher).

        INPUT:

        - ``component`` -- **Component object**; the output component (intermediate or cipher) in Cipher

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: output_component = speck.component_from(0, 5)
            sage: cp.output_constraints(output_component)
            ([],
             ['constraint intermediate_output_0_5[0] = key[48];',
             ...
              'constraint intermediate_output_0_5[15] = key[63];'])
        """
        output_size = int(component.output_bit_size)
        input_id_links = component.input_id_links
        output_id_link = component.id
        input_bit_positions = component.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[i]};' for i in range(output_size)]

        return cp_declarations, cp_constraints

    def output_inverse_constraints(self, component):
        """
        Return lists of declarations and constraints for CP output component (both intermediate and cipher).

        INPUT:

        - ``component`` -- **Component object**; the output component (intermediate or cipher)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: output_component = speck.component_from(0, 5)
            sage: cp.output_inverse_constraints(output_component)
            ([],
             ['constraint intermediate_output_0_5_inverse[0] = key[48];',
               ...
              'constraint intermediate_output_0_5_inverse[15] = key[63];'])
        """
        output_size = int(component.output_bit_size)
        input_id_links = component.input_id_links
        output_id_link = component.id
        input_bit_positions = component.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = [f'constraint {output_id_link}_inverse[{i}] = {all_inputs[i]};'
                          for i in range(output_size)]

        return cp_declarations, cp_constraints
