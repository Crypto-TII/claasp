
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


from claasp.cipher_modules.models.cp.cp_model import solve_satisfy
from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel

from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL)


class CpImpossibleXorDifferentialModel(CpDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher):
        super().__init__(cipher)
        self.inverse_cipher = cipher.cipher_inverse()

    def add_solution_to_components_values(self, component_id, component_solution, components_values, j, output_to_parse,
                                          solution_number, string):
        inverse_cipher = self.inverse_cipher
        if component_id in self._cipher.inputs or component_id in inverse_cipher.inputs:
            component_solution['weight'] = 0
            components_values[f'solution{solution_number}'][f'{component_id}'] = component_solution
        elif f'{component_id}_i' in string:
            component_solution['weight'] = float(output_to_parse[j + 2])
            components_values[f'solution{solution_number}'][f'{component_id}_i'] = component_solution
        elif f'{component_id}_o' in string:
            component_solution['weight'] = float(output_to_parse[j + 1])
            components_values[f'solution{solution_number}'][f'{component_id}_o'] = component_solution
        elif f'{component_id} ' in string:
            component_solution['weight'] = float(output_to_parse[j + 1])
            components_values[f'solution{solution_number}'][f'{component_id}'] = component_solution

    def build_impossible_xor_differential_trail_model(self, fixed_variables=[], number_of_rounds=None, middle_round=1):
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
            sage: cp.build_impossible_xor_differential_trail_model(fixed_variables)
        """
        self.initialise_model()
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds
        inverse_cipher = self.inverse_cipher

        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        deterministic_truncated_xor_differential = constraints

        forward_components = []
        for r in range(middle_round):
            forward_components.extend(self._cipher.get_components_in_round(r))
        backward_components = []
        for r in range(number_of_rounds - middle_round + 1):
            backward_components.extend(inverse_cipher.get_components_in_round(r))
        
        for component in forward_components:
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                               SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'OR', 'MODADD', 'MODSUB', 'NOT', 'ROTATE', 'SHIFT', 'XOR']
            if component.type not in component_types or \
                    (component.type == WORD_OPERATION and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            if component.type == SBOX:
                variables, constraints, sbox_mant = component.cp_deterministic_truncated_xor_differential_trail_constraints(self.sbox_mant)
                self.sbox_mant = sbox_mant
            else:
                variables, constraints = component.cp_deterministic_truncated_xor_differential_trail_constraints()
            self._variables_list.extend(variables)
            deterministic_truncated_xor_differential.extend(constraints)

        inverse_variables = []
        inverse_constraints = []
        for component in backward_components:
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                               SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'OR', 'MODADD', 'MODSUB', 'NOT', 'ROTATE', 'SHIFT', 'XOR']
            if component.type not in component_types or \
                    (component.type == WORD_OPERATION and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            if component.type == SBOX:
                variables, constraints, sbox_mant = component.cp_deterministic_truncated_xor_differential_trail_constraints(self.sbox_mant, inverse = True)
                self.sbox_mant = sbox_mant
            else:
                variables, constraints = component.cp_deterministic_truncated_xor_differential_trail_constraints()
            inverse_variables.extend(variables)
            inverse_constraints.extend(constraints)
            
        for component in backward_components:
            for v in range(len(inverse_variables)):
                start = 0
                while component.id in inverse_variables[v][start:]:
                    new_start = inverse_variables[v].index(component.id, start)
                    inverse_variables[v] = inverse_variables[v][:new_start] + 'inverse_' + inverse_variables[v][new_start:]
                    start = new_start + 9
            for c in range(len(inverse_constraints)):
                start = 0
                while component.id in inverse_constraints[c][start:]:
                    new_start = inverse_constraints[c].index(component.id, start)
                    inverse_constraints[c] = inverse_constraints[c][:new_start] + 'inverse_' + inverse_constraints[c][new_start:]
                    start = new_start + 9
        for c in range(len(inverse_constraints)):
            start = 0
            while 'cipher_output' in inverse_constraints[c][start:]:
                new_start = inverse_constraints[c].index('cipher_output', start)
                inverse_constraints[c] = inverse_constraints[c][:new_start] + 'inverse_' + inverse_constraints[c][new_start:]
                start = new_start + 9
            start = 0
            while 'inverse_inverse_' in inverse_constraints[c][start:]:
                new_start = inverse_constraints[c].index('inverse_inverse_', start)
                inverse_constraints[c] = inverse_constraints[c][:new_start] + inverse_constraints[c][new_start + 8:]
                start = new_start
        for v in range(len(inverse_variables)):
            start = 0
            while 'inverse_inverse_' in inverse_variables[v][start:]:
                new_start = inverse_variables[v].index('inverse_inverse_', start)
                inverse_variables[v] = inverse_variables[v][:new_start] + inverse_variables[v][new_start + 8:]
                start = new_start
                 
        self._variables_list.extend(inverse_variables)
        deterministic_truncated_xor_differential.extend(inverse_constraints)

        print('1')

        variables, constraints = self.input_deterministic_truncated_xor_differential_constraints(number_of_rounds = number_of_rounds, middle_round = middle_round)
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        deterministic_truncated_xor_differential.extend(
            self.final_impossible_constraints(middle_round))
        self._model_constraints = self._model_prefix + self._variables_list + deterministic_truncated_xor_differential

    def final_impossible_constraints(self, middle_round):
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
        inverse_cipher = self.inverse_cipher
        cipher_outputs = inverse_cipher.inputs
        cp_constraints = [solve_satisfy]
        new_constraint = 'output['
        incompatibility_constraint = 'constraint'
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for element in cipher_outputs:
            new_constraint = f'{new_constraint}\"inverse_{element} = \"++ show(inverse_{element}) ++ \"\\n\" ++'
        for component in cipher.get_components_in_round(middle_round-1):
            component_id = component.id
            output_bit_size = component.output_bit_size
            new_constraint = new_constraint + \
                f'\"{component_id} = \"++ show({component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
            new_constraint = new_constraint + \
                f'\"inverse_{component_id} = \"++ show(inverse_{component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
            for i in range(output_bit_size):
                incompatibility_constraint += f'({component_id}[{i}]+inverse_{component_id}[{i}]=1) \\/ '
            #else:
            #    new_constraint = new_constraint + \
            #        f'\"{component_id}_inverse = \"++ show({component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        incompatibility_constraint = incompatibility_constraint[:-4] + ';'
        new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(incompatibility_constraint)
        cp_constraints.append(new_constraint)

        return cp_constraints
        
    def find_all_impossible_xor_differential_trails(self, number_of_rounds,
                                                                fixed_values=[], solver_name=None, middle_round=1):
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
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, middle_round)

        return self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name)

    def find_one_impossible_xor_differential_trail(self, number_of_rounds=None,
                                                                fixed_values=[], solver_name=None, middle_round=1):
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
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, middle_round)

        return self.solve('impossible_xor_differential_one_solution', solver_name)

