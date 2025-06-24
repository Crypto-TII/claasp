
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

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.utils import constants, utils
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.utils.constants import OUTPUT_BIT_ID_SUFFIX, INPUT_BIT_ID_SUFFIX
from claasp.cipher_modules.models.utils import get_bit_bindings, set_component_solution, \
    get_single_key_scenario_format_for_fixed_values
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER,
                                  MIX_COLUMN, SBOX, WORD_OPERATION, XOR_LINEAR, INPUT_KEY)


class SatXorLinearModel(SatModel):
    def __init__(self, cipher, counter='sequential', compact=False):
        super().__init__(cipher, counter, compact)
        self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(cipher, '_'.join)

    @staticmethod
    def branch_xor_linear_constraints(bindings):
        """
        Return lists of variables and clauses for branch in XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorLinearModel(speck)
            sage: SatXorLinearModel.branch_xor_linear_constraints(sat.bit_bindings)
            ['-plaintext_0_o rot_0_0_0_i',
             'plaintext_0_o -rot_0_0_0_i',
             '-plaintext_1_o rot_0_0_1_i',
             ...
             'xor_2_10_14_o -cipher_output_2_12_30_i',
             '-xor_2_10_15_o cipher_output_2_12_31_i',
             'xor_2_10_15_o -cipher_output_2_12_31_i']
        """
        constraints = []
        for output_bit, input_bits in bindings.items():
            constraints.extend(utils.cnf_xor(output_bit, input_bits))

        return constraints

    def build_xor_linear_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the linear model.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`)
        - ``fixed_variables`` -- **list** (default: `[]`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: sat = SatXorLinearModel(speck)
            sage: sat.build_xor_linear_trail_model()
        """
        self._variables_list = []
        variables = []
        if INPUT_KEY not in [variable["component_id"] for variable in fixed_variables]:
            self._cipher = self._cipher.remove_key_schedule()
            self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(self._cipher, '_'.join)
        if fixed_variables == []:
            fixed_variables = get_single_key_scenario_format_for_fixed_values(self._cipher)
        constraints = SatXorLinearModel.fix_variables_value_xor_linear_constraints(fixed_variables)
        self._model_constraints = constraints
        component_types = (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN, WORD_OPERATION)
        operation_types = ("AND", "MODADD", "NOT", "ROTATE", "SHIFT", "XOR", "OR", "MODSUB")

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.sat_xor_linear_mask_propagation_constraints(self)
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        constraints = SatXorLinearModel.branch_xor_linear_constraints(self.bit_bindings)
        self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self.weight_xor_linear_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def find_all_xor_linear_trails_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                     solver_name=solvers.SOLVER_DEFAULT):
        """
        Return a list of solutions containing all the XOR linear trails having weight equal to ``fixed_weight``.
        By default, the search removes the key schedule, if any.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorLinearModel(speck)
            sage: trails = sat.find_all_xor_linear_trails_with_fixed_weight(1)
            sage: len(trails) == 4
            True

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
            sage: sat = SatXorLinearModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(16)), [0] * 16)
            sage: trails = sat.find_all_xor_linear_trails_with_fixed_weight(2, fixed_values=[key])
            sage: len(trails) == 8
            True
        """
        start_building_time = time.time()
        self.build_xor_linear_trail_model(weight=fixed_weight, fixed_variables=fixed_values)
        if self._counter == self._sequential_counter:
            self._sequential_counter_greater_or_equal(fixed_weight, 'dummy_hw_1')
        end_building_time = time.time()
        solution = self.solve(XOR_LINEAR, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        solutions_list = []
        while solution['total_weight'] is not None:
            solutions_list.append(solution)
            literals = []
            for component in solution['components_values']:
                value_as_hex_string = solution['components_values'][component]['value']
                value_to_avoid = int(value_as_hex_string, base=16)
                bit_len = (len(value_as_hex_string) - 2) * 4
                minus = ['-' * (value_to_avoid >> i & 1) for i in reversed(range(bit_len))]
                if CONSTANT in component and component.endswith(INPUT_BIT_ID_SUFFIX):
                    continue
                elif component.endswith(INPUT_BIT_ID_SUFFIX) or component.endswith(OUTPUT_BIT_ID_SUFFIX):
                    component_id = component[:-2]
                    suffix = component[-2:]
                else:
                    component_id = component
                    suffix = OUTPUT_BIT_ID_SUFFIX
                literals.extend([f'{minus[i]}{component_id}_{i}{suffix}' for i in range(bit_len)])
            self._model_constraints.append(' '.join(literals))
            solution = self.solve(XOR_LINEAR, solver_name=solver_name)
            solution['building_time_seconds'] = end_building_time - start_building_time
            solution['test_name'] = "find_all_xor_linear_trails_with_fixed_weight"
        return solutions_list

    def find_all_xor_linear_trails_with_weight_at_most(self, min_weight, max_weight, fixed_values=[],
                                                       solver_name=solvers.SOLVER_DEFAULT):
        """
        Return a list of solutions.
        By default, the search removes the key schedule, if any.

        The list contains all the XOR linear trails having the weight lying in the interval
        ``[min_weight, max_weight]``.

        INPUT:

        - ``min_weight`` -- **integer**; the weight from which to start the search
        - ``max_weight`` -- **integer**; the weight at which the search stops
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorLinearModel(speck)
            sage: trails = sat.find_all_xor_linear_trails_with_weight_at_most(0, 2) # long
            sage: len(trails) == 187
            True

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
            sage: sat = SatXorLinearModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(16)), [0] * 16)
            sage: trails = sat.find_all_xor_linear_trails_with_weight_at_most(0, 3, fixed_values=[key]) # long
            sage: len(trails) == 73
            True
        """
        solutions_list = []
        for weight in range(min_weight, max_weight + 1):
            solutions = self.find_all_xor_linear_trails_with_fixed_weight(weight,
                                                                          fixed_values=fixed_values,
                                                                          solver_name=solver_name)
            for solution in solutions:
                solution['test_name'] = "find_all_xor_linear_trails_with_weight_at_most"
            solutions_list.extend(solutions)

        return solutions_list

    def find_lowest_weight_xor_linear_trail(self, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Return the solution representing a XOR LINEAR trail with the lowest possible weight.
        By default, the search removes the key schedule, if any.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        .. NOTE::

            There could be more than one trail with the lowest weight. In order to find all the lowest weight trail,
            run :py:meth:`~SatXorLinearModel.find_all_xor_linear_trails_with_fixed_weight`.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorLinearModel(speck)
            sage: trail = sat.find_lowest_weight_xor_linear_trail()
            sage: trail['total_weight']
            1.0

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=4)
            sage: sat = SatXorLinearModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(32)), [0] * 32)
            sage: trail = sat.find_lowest_weight_xor_linear_trail(fixed_values=[key])
            sage: trail['total_weight']
            3.0
        """
        current_weight = 0
        start_building_time = time.time()
        self.build_xor_linear_trail_model(weight=current_weight, fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(XOR_LINEAR, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        total_time = solution['solving_time_seconds']
        max_memory = solution['memory_megabytes']
        while solution['total_weight'] is None:
            current_weight += 1
            start_building_time = time.time()
            self.build_xor_linear_trail_model(weight=current_weight, fixed_variables=fixed_values)
            end_building_time = time.time()
            solution = self.solve(XOR_LINEAR, solver_name=solver_name)
            solution['building_time_seconds'] = end_building_time - start_building_time
            total_time += solution['solving_time_seconds']
            max_memory = max((max_memory, solution['memory_megabytes']))
        solution['solving_time_seconds'] = total_time
        solution['memory_megabytes'] = max_memory
        solution['test_name'] = "find_lowest_weight_xor_linear_trail"

        return solution

    def find_one_xor_linear_trail(self, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Return the solution representing a XOR linear trail.
        By default, the search removes the key schedule, if any.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        The solution probability is almost always lower than the one of a random guess of the longest input.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: sat = SatXorLinearModel(speck)
            sage: sat.find_one_xor_linear_trail() # random
            {'cipher_id': 'speck_p32_k64_o32_r4',
             'model_type': 'xor_linear',
             'solver_name': 'cryptominisat',
             'solving_time_seconds': 0.01,
             'memory_megabytes': 7.2,
             ...
             'status': 'SATISFIABLE',
             'building_time_seconds': 0.010079622268676758}

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: sat = SatXorLinearModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(64)), [0] * 64)
            sage: sat.find_one_xor_linear_trail(fixed_values=[key]) # random
        """
        start_building_time = time.time()
        self.build_xor_linear_trail_model(fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(XOR_LINEAR, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        solution['test_name'] = "find_one_xor_linear_trail"

        return solution

    def find_one_xor_linear_trail_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                    solver_name=solvers.SOLVER_DEFAULT):
        """
        Return the solution representing a XOR linear trail whose weight is ``fixed_weight``.
        By default, the search removes the key schedule, if any.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorLinearModel(speck)
            sage: trail = sat.find_one_xor_linear_trail_with_fixed_weight(7)
            sage: trail['total_weight']
            7.0

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
            sage: sat = SatXorLinearModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(16)), [0] * 16)
            sage: trail = sat.find_one_xor_linear_trail_with_fixed_weight(3, fixed_values=[key])
            sage: trail['total_weight']
            3.0
        """
        start_building_time = time.time()
        self.build_xor_linear_trail_model(weight=fixed_weight, fixed_variables=fixed_values)
        if self._counter == self._sequential_counter:
            self._sequential_counter_greater_or_equal(fixed_weight, 'dummy_hw_1')
        end_building_time = time.time()
        solution = self.solve(XOR_LINEAR, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        solution['test_name'] = "find_one_xor_linear_trail_with_fixed_weight"

        return solution

    @staticmethod
    def fix_variables_value_xor_linear_constraints(fixed_variables=[]):
        """
        Return lists variables and clauses for fixing variables in XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); variables in default format

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorLinearModel(speck)
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'ciphertext',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 1, 1, 0]
            ....: }]
            sage: SatXorLinearModel.fix_variables_value_xor_linear_constraints(fixed_variables)
            ['plaintext_0_o',
             '-plaintext_1_o',
             'plaintext_2_o',
             'plaintext_3_o',
             '-ciphertext_0_o -ciphertext_1_o -ciphertext_2_o ciphertext_3_o']
        """
        constraints = []
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        for variable in fixed_variables:
            component_id = variable['component_id']
            is_equal = (variable['constraint_type'] == 'equal')
            bit_positions = variable['bit_positions']
            bit_values = variable['bit_values']
            variables_ids = []
            for position, value in zip(bit_positions, bit_values):
                is_negative = '-' * (value ^ is_equal)
                variables_ids.append(f'{is_negative}{component_id}_{position}{out_suffix}')
            if is_equal:
                constraints.extend(variables_ids)
            else:
                constraints.append(' '.join(variables_ids))

        return constraints

    def weight_xor_linear_constraints(self, weight):
        return self.weight_constraints(weight)

    def _parse_solver_output(self, variable2value):
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        in_suffix = constants.INPUT_BIT_ID_SUFFIX
        components_solutions = self._get_cipher_inputs_components_solutions(out_suffix, variable2value)
        total_weight = 0
        for component in self._cipher.get_all_components():
            hex_solution = self._get_component_hex_value(component, out_suffix, variable2value)
            weight = self.calculate_component_weight(component, out_suffix, variable2value)
            component_solution = set_component_solution(hex_solution, weight)
            components_solutions[f'{component.id}{out_suffix}'] = component_solution
            total_weight += weight

            input_hex_value = self._get_component_hex_value(component, in_suffix, variable2value)
            component_solution = set_component_solution(input_hex_value, 0)
            components_solutions[f'{component.id}{in_suffix}'] = component_solution

        return components_solutions, total_weight
