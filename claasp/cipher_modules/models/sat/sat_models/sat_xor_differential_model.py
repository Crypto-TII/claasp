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
from copy import deepcopy

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
from claasp.cipher_modules.models.utils import set_component_solution, get_single_key_scenario_format_for_fixed_values
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER,
                                  MIX_COLUMN, SBOX, WORD_OPERATION, XOR_DIFFERENTIAL)


class SatXorDifferentialModel(SatModel):
    def __init__(self, cipher, window_size_weight_pr_vars=-1, counter='sequential', compact=False):
        self._window_size_by_component_id_values = None
        self._window_size_by_round_values = None
        self._window_size_full_window_vars = None
        self._window_size_number_of_full_window = None
        self._window_size_full_window_operator = None
        super().__init__(cipher, window_size_weight_pr_vars, counter, compact)

    def build_xor_differential_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the model for the search of XOR DIFFERENTIAL trails.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight
        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: sat = SatXorDifferentialModel(speck)
            sage: sat.build_xor_differential_trail_model()
        """
        variables = []
        self._variables_list = []
        if fixed_variables == []:
            fixed_variables = get_single_key_scenario_format_for_fixed_values(self._cipher)
        constraints = self.fix_variables_value_constraints(fixed_variables)
        self._model_constraints = constraints
        component_types = (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN, WORD_OPERATION)
        operation_types = ('AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR')

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                    WORD_OPERATION == component.type and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            else:
                variables, constraints = component.sat_xor_differential_propagation_constraints(self)

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self.weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if self._window_size_full_window_vars is not None:
            self._variables_list.extend(self._window_size_full_window_vars)

            if self._window_size_number_of_full_window == 0:
                self._variables_list.extend([])
                self._model_constraints.extend([f'-{variable}' for variable in self._window_size_full_window_vars])
                return


            if self._window_size_full_window_operator == 'at_least':
                all_ones_dummy_variables, all_ones_constraints = self._sequential_counter_algorithm(
                    self._window_size_full_window_vars,
                    self._window_size_number_of_full_window - 1,
                    'dummy_all_ones_at_least',
                    greater_or_equal=True
                )
            elif self._window_size_full_window_operator == 'at_most':
                all_ones_dummy_variables, all_ones_constraints = self._sequential_counter_algorithm(
                    self._window_size_full_window_vars,
                    self._window_size_number_of_full_window,
                    'dummy_all_ones_at_most',
                    greater_or_equal=False
                )
            elif self._window_size_full_window_operator == 'exactly':
                all_ones_dummy_variables1, all_ones_constraints1 = self._sequential_counter_algorithm(
                    self._window_size_full_window_vars,
                    self._window_size_number_of_full_window,
                    'dummy_all_ones_at_least',
                    greater_or_equal=True
                )
                all_ones_dummy_variables2, all_ones_constraints2 = self._sequential_counter_algorithm(
                    self._window_size_full_window_vars,
                    self._window_size_number_of_full_window,
                    'dummy_all_ones_at_most',
                    greater_or_equal=False
                )
                all_ones_dummy_variables = all_ones_dummy_variables1 + all_ones_dummy_variables2
                all_ones_constraints = all_ones_constraints1 + all_ones_constraints2
            else:
                raise ValueError(f'Unknown operator {self._window_size_full_window_operator}')


            self._variables_list.extend(all_ones_dummy_variables)
            self._model_constraints.extend(all_ones_constraints)

    def build_xor_differential_trail_and_checker_model_at_intermediate_output_level(
            self, weight=-1, fixed_variables=[]
    ):
        """
        Build the model for the search of XOR DIFFERENTIAL trails and the model to check that there is at least one pair
        satisfying such trails at the intermediate output level.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight
        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: sat = SatXorDifferentialModel(speck)
            sage: sat.build_xor_differential_trail_and_checker_model_at_intermediate_output_level()
        """
        self.build_xor_differential_trail_model(weight, fixed_variables)
        internal_cipher = deepcopy(self._cipher)
        internal_cipher.convert_to_compound_xor_cipher()
        sat = SatCipherModel(internal_cipher)
        sat.build_cipher_model()
        self._variables_list.extend(sat._variables_list)
        self._model_constraints.extend(sat._model_constraints)

    def find_all_xor_differential_trails_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                           solver_name=solvers.SOLVER_DEFAULT):
        """
        Return a list of solutions containing all the XOR differential trails having the ``fixed_weight`` weight.
        By default, the search is set in the single-key setting.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: sat = SatXorDifferentialModel(speck)
            sage: trails = sat.find_all_xor_differential_trails_with_fixed_weight(9)
            sage: len(trails) == 2
            True

            # related-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: sat = SatXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: trails = sat.find_all_xor_differential_trails_with_fixed_weight(2, fixed_values=[key])
            sage: len(trails) == 2
            True
        """
        start_building_time = time.time()
        self.build_xor_differential_trail_model(weight=fixed_weight, fixed_variables=fixed_values)
        if self._counter == self._sequential_counter:
            self._sequential_counter_greater_or_equal(fixed_weight, 'dummy_hw_1')
        end_building_time = time.time()
        solution = self.solve(XOR_DIFFERENTIAL, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        solutions_list = []
        while solution['total_weight'] is not None:
            solutions_list.append(solution)
            literals = []
            for input_, bit_len in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
                value_to_avoid = int(solution['components_values'][input_]['value'], base=16)
                minus = ['-' * (value_to_avoid >> i & 1) for i in reversed(range(bit_len))]
                literals.extend([f'{minus[i]}{input_}_{i}' for i in range(bit_len)])
            for component in self._cipher.get_all_components():
                bit_len = component.output_bit_size
                if component.type == SBOX or \
                        (component.type == WORD_OPERATION and
                         component.description[0] in ('AND', 'MODADD', 'MODSUB', 'OR', 'SHIFT_BY_VARIABLE_AMOUNT')):
                    value_to_avoid = int(solution['components_values'][component.id]['value'], base=16)
                    minus = ['-' * (value_to_avoid >> i & 1) for i in reversed(range(bit_len))]
                    literals.extend([f'{minus[i]}{component.id}_{i}' for i in range(bit_len)])
            self._model_constraints.append(' '.join(literals))
            solution = self.solve(XOR_DIFFERENTIAL, solver_name=solver_name)
            solution['building_time_seconds'] = end_building_time - start_building_time
            solution['test_name'] = "find_all_xor_differential_trails_with_fixed_weight"
        return solutions_list

    def find_all_xor_differential_trails_with_weight_at_most(self, min_weight, max_weight, fixed_values=[],
                                                             solver_name=solvers.SOLVER_DEFAULT):
        """
        Return a list of solutions.
        By default, the search is set in the single-key setting.

        The list contain all the XOR differential trails having the weight lying in the interval
        ``[min_weight, max_weight]``.

        INPUT:

        - ``min_weight`` -- **integer**; the weight from which to start the search
        - ``max_weight`` -- **integer**; the weight at which the search stops
        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: sat = SatXorDifferentialModel(speck)
            sage: trails = sat.find_all_xor_differential_trails_with_weight_at_most(9, 10)
            sage: len(trails) == 28
            True

            # related-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: sat = SatXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: trails = sat.find_all_xor_differential_trails_with_weight_at_most(2, 3, fixed_values=[key])
            sage: len(trails) == 9
            True
        """
        solutions_list = []
        for weight in range(min_weight, max_weight + 1):
            solutions = self.find_all_xor_differential_trails_with_fixed_weight(weight,
                                                                                fixed_values=fixed_values,
                                                                                solver_name=solver_name)

            for solution in solutions:
                solution['test_name'] = "find_all_xor_differential_trails_with_weight_at_most"
            solutions_list.extend(solutions)

        return solutions_list

    def find_lowest_weight_xor_differential_trail(self, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Return the solution representing a trail with the lowest weight.
        By default, the search is set in the single-key setting.

        .. NOTE::

            There could be more than one trail with the lowest weight. In order to find all the lowest weight trail,
            run :py:meth:`~SatXorDifferentialModel.find_all_xor_differential_trails_with_fixed_weight`.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: sat = SatXorDifferentialModel(speck)
            sage: trail = sat.find_lowest_weight_xor_differential_trail()
            sage: trail['total_weight']
            9.0

            # related-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: sat = SatXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:         component_id='key',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(64),
            ....:         bit_values=(0,)*64)
            sage: trail = sat.find_lowest_weight_xor_differential_trail(fixed_values=[key])
            sage: trail['total_weight']
            1.0
        """
        current_weight = 0
        start_building_time = time.time()
        self.build_xor_differential_trail_model(weight=current_weight, fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(XOR_DIFFERENTIAL, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        total_time = solution['solving_time_seconds']
        max_memory = solution['memory_megabytes']
        while solution['total_weight'] is None:
            current_weight += 1
            start_building_time = time.time()
            self.build_xor_differential_trail_model(weight=current_weight, fixed_variables=fixed_values)
            end_building_time = time.time()
            solution = self.solve(XOR_DIFFERENTIAL, solver_name=solver_name)
            solution['building_time_seconds'] = end_building_time - start_building_time
            total_time += solution['solving_time_seconds']
            max_memory = max((max_memory, solution['memory_megabytes']))
        solution['solving_time_seconds'] = total_time
        solution['memory_megabytes'] = max_memory
        solution['test_name'] = "find_lowest_weight_xor_differential_trail"

        return solution

    def find_one_xor_differential_trail(self, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Return the solution representing a XOR differential trail.
        By default, the search is set in the single-key setting.
        The solution probability is almost always lower than the one of a random guess of the longest input.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: sat = SatXorDifferentialModel(speck)
            sage: sat.find_one_xor_differential_trail() # random

            # related-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: sat = SatXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: result = sat.find_one_xor_differential_trail(fixed_values=[key])
            sage: result['total_weight'] == 9.0
            True
        """
        start_building_time = time.time()
        self.build_xor_differential_trail_model(fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(XOR_DIFFERENTIAL, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        solution['test_name'] = "find_one_xor_differential_trail"

        return solution

    def find_one_xor_differential_trail_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                          solver_name=solvers.SOLVER_DEFAULT):
        """
        Return the solution representing a XOR differential trail whose probability is ``2 ** fixed_weight``.
        By default, the search is set in the single-key setting.
        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorDifferentialModel(speck)
            sage: sat.set_window_size_heuristic_by_round([0, 0, 0])
            sage: trail = sat.find_one_xor_differential_trail_with_fixed_weight(3)
            ...
            sage: trail['total_weight']
            3.0

            # related-key setting
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: trail = sat.find_one_xor_differential_trail_with_fixed_weight(3, fixed_values=[key])
            sage: trail['total_weight']
            3.0
        """
        start_building_time = time.time()
        self.build_xor_differential_trail_model(weight=fixed_weight, fixed_variables=fixed_values)
        if self._counter == self._sequential_counter:
            self._sequential_counter_greater_or_equal(fixed_weight, 'dummy_hw_1')
        end_building_time = time.time()
        solution = self.solve(XOR_DIFFERENTIAL, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        solution['test_name'] = "find_one_xor_differential_trail_with_fixed_weight"

        return solution

    def _parse_solver_output(self, variable2value):
        out_suffix = ''
        components_solutions = self._get_cipher_inputs_components_solutions(out_suffix, variable2value)
        total_weight = 0
        for component in self._cipher.get_all_components():
            hex_value = self._get_component_hex_value(component, out_suffix, variable2value)
            weight = self.calculate_component_weight(component, out_suffix, variable2value)
            component_solution = set_component_solution(hex_value, weight)
            components_solutions[f'{component.id}{out_suffix}'] = component_solution
            total_weight += weight

        return components_solutions, total_weight

    def set_window_size_heuristic_by_round(
            self, window_size_by_round_values, number_of_full_windows=None, full_window_operator='at_least'
    ):
        if not self._cipher.is_arx():
            raise Exception('Cipher is not ARX. Window Size Heuristic is only supported for ARX ciphers.')
        self._window_size_by_round_values = window_size_by_round_values
        if number_of_full_windows is not None:
            self._window_size_full_window_vars = []
            self._window_size_number_of_full_window = number_of_full_windows
            self._window_size_full_window_operator = full_window_operator

    def set_window_size_heuristic_by_component_id(
            self, window_size_by_component_id_values, number_of_full_windows=None, full_window_operator='at_least'
    ):
        if not self._cipher.is_arx():
            raise Exception('Cipher is not ARX. Window Size Heuristic is only supported for ARX ciphers.')
        self._window_size_by_component_id_values = window_size_by_component_id_values
        if number_of_full_windows is not None:
            self._window_size_full_window_vars = []
            self._window_size_number_of_full_window = number_of_full_windows
            self._window_size_full_window_operator = full_window_operator

    @property
    def window_size_number_of_full_window(self):
        return self._window_size_number_of_full_window

    @property
    def window_size_full_window_vars(self):
        return self._window_size_full_window_vars

    @property
    def window_size_by_round_values(self):
        return self._window_size_by_round_values

    @property
    def window_size_by_component_id_values(self):
        return self._window_size_by_component_id_values
