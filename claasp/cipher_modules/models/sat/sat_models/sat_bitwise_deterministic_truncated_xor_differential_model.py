
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


import time

from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL,
                                  INTERMEDIATE_OUTPUT, INPUT_PLAINTEXT, LINEAR_LAYER, MIX_COLUMN, SBOX, WORD_OPERATION)


class SatBitwiseDeterministicTruncatedXorDifferentialModel(SatModel):
    def __init__(self, cipher, window_size_weight_pr_vars=-1, counter='sequential', compact=False):
        super().__init__(cipher, window_size_weight_pr_vars, counter, compact)

    def build_bitwise_deterministic_truncated_xor_differential_trail_model(self, number_of_unknown_variables=None, fixed_variables=[]):
        """
        Build the model for the search of deterministic truncated XOR DIFFERENTIAL trails.

        INPUT:

        - ``number_of_unknown_variables`` -- **int** (default: None); the number
          of unknown variables that we want to have in the trail
        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be
          fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatBitwiseDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: sat = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: sat.build_bitwise_deterministic_truncated_xor_differential_trail_model()
            ...
        """
        variables = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        self._variables_list = []
        self._model_constraints = constraints
        component_types = (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, SBOX, WORD_OPERATION)
        operation_types = ('AND', 'MODADD', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR')

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if number_of_unknown_variables is not None:
            variables, constraints = self.weight_constraints(number_of_unknown_variables)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def fix_variables_value_constraints(self, fixed_variables=[]):
        """
        Return constraints for fixed variables

        Return lists of variables and clauses for fixing variables in bitwise
        deterministic truncated XOR differential model.

        .. SEEALSO::

           :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); variables in default format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatBitwiseDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'ciphertext',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [2, 1, 1, 0]
            ....: }]
            sage: sat.fix_variables_value_constraints(fixed_variables)
            ['-plaintext_0_0',
             'plaintext_0_1',
             '-plaintext_1_0',
             '-plaintext_1_1',
             '-plaintext_2_0',
             'plaintext_2_1',
             '-plaintext_3_0',
             'plaintext_3_1',
             '-ciphertext_0_0 ciphertext_1_0 -ciphertext_1_1 ciphertext_2_0 -ciphertext_2_1 ciphertext_3_0 ciphertext_3_1']
        """
        constraints = []
        for variable in fixed_variables:
            component_id = variable['component_id']
            is_equal = (variable['constraint_type'] == 'equal')
            bit_positions = variable['bit_positions']
            bit_values = variable['bit_values']
            variables_ids = []
            for position, value in zip(bit_positions, bit_values):
                false_sign = '-' * is_equal
                true_sign = '-' * (not is_equal)
                if value == 0:
                    variables_ids.append(f'{false_sign}{component_id}_{position}_0')
                    variables_ids.append(f'{false_sign}{component_id}_{position}_1')
                elif value == 1:
                    variables_ids.append(f'{false_sign}{component_id}_{position}_0')
                    variables_ids.append(f'{true_sign}{component_id}_{position}_1')
                elif value == 2:
                    variables_ids.append(f'{true_sign}{component_id}_{position}_0')
            if is_equal:
                constraints.extend(variables_ids)
            else:
                constraints.append(' '.join(variables_ids))

        return constraints

    def find_one_bitwise_deterministic_truncated_xor_differential_trail(self, fixed_values=[],
                                                                        solver_name='cryptominisat'):
        """
        Returns one deterministic truncated XOR differential trail.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatBitwiseDeterministicTruncatedXorDifferentialModel
            sage: M = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: trail = M.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
            ...

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatBitwiseDeterministicTruncatedXorDifferentialModel
            sage: M = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: out = set_fixed_variables(component_id='cipher_output_2_12', constraint_type='equal', bit_positions=range(32), bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            sage: trail = M.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key, out]) # doctest: +SKIP
            ...

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: present = PresentBlockCipher(number_of_rounds=1)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatBitwiseDeterministicTruncatedXorDifferentialModel
            sage: sat = SatBitwiseDeterministicTruncatedXorDifferentialModel(present)
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(80), bit_values=[0]*80)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(64), bit_values=[2,0,0,0] + [1,0,0,1] + [0,0,0,1] + [1,0,0,0] + [0] * 48)
            sage: trail = sat.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key]) # doctest: +SKIP
            ...

        """
        start_building_time = time.time()
        self.build_bitwise_deterministic_truncated_xor_differential_trail_model(fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time

        return solution

    def find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name='cryptominisat'):
        """
        Return the solution representing a differential trail with the lowest number of unknown variables.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatBitwiseDeterministicTruncatedXorDifferentialModel
            sage: S = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: trail = S.find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(speck))
            sage: trail['status']
            'SATISFIABLE'
        """
        current_unknowns_count = 1
        start_building_time = time.time()
        self.build_bitwise_deterministic_truncated_xor_differential_trail_model(
            number_of_unknown_variables=current_unknowns_count, fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        total_time = solution['solving_time_seconds']
        max_memory = solution['memory_megabytes']
        while solution['status'] != 'SATISFIABLE':
            current_unknowns_count += 1
            start_building_time = time.time()
            self.build_bitwise_deterministic_truncated_xor_differential_trail_model(
                number_of_unknown_variables=current_unknowns_count, fixed_variables=fixed_values)
            end_building_time = time.time()
            solution = self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name=solver_name)
            solution['building_time_seconds'] = end_building_time - start_building_time
            total_time += solution['solving_time_seconds']
            max_memory = max((max_memory, solution['memory_megabytes']))
        solution['solving_time_seconds'] = total_time
        solution['memory_megabytes'] = max_memory

        return solution

    def weight_constraints(self, number_of_unknown_variables):
        """
        Return lists of variables and constraints that fix the number of unknown
        variables of the input and the output of the trail to a specific value.

        INPUT:

        - ``number_of_unknown_variables`` -- **int**; the number of the unknown variables

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import SatBitwiseDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: sat.build_bitwise_deterministic_truncated_xor_differential_trail_model()
            sage: sat.weight_constraints(4)
            (['dummy_hw_0_0_0',
              'dummy_hw_0_0_1',
              'dummy_hw_0_0_2',
              ...
              '-dummy_hw_0_61_3 dummy_hw_0_62_3',
              '-cipher_output_2_12_30_0 -dummy_hw_0_61_3',
              '-cipher_output_2_12_31_0 -dummy_hw_0_62_3'])
        """
        cipher_output_id = self._cipher.get_all_components_ids()[-1]
        set_to_be_minimized = [f"{INPUT_PLAINTEXT}_{i}_0"
                               for i in range(self._cipher.inputs_bit_size[self._cipher.inputs.index(INPUT_PLAINTEXT)])]
        set_to_be_minimized.extend([bit_id for bit_id in self._variables_list
                                    if bit_id.startswith(cipher_output_id) and bit_id.endswith("_0")])

        return self._counter(set_to_be_minimized, number_of_unknown_variables)

    def _parse_solver_output(self, variable2value):
        components_solutions = self._get_cipher_inputs_components_solutions_double_ids(variable2value)
        for component in self._cipher.get_all_components():
            value = self._get_component_value_double_ids(component, variable2value)
            component_solution = set_component_solution(value)
            components_solutions[f'{component.id}'] = component_solution

        return components_solutions, None
