
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

from claasp.cipher_modules.models.smt import solvers
from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.cipher_modules.models.smt.utils import constants, utils
from claasp.cipher_modules.models.utils import set_component_solution, get_single_key_scenario_format_for_fixed_values
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER,
                                  MIX_COLUMN, SBOX, WORD_OPERATION, XOR_DIFFERENTIAL)


class SmtXorDifferentialModel(SmtModel):
    def __init__(self, cipher, counter='sequential'):
        super().__init__(cipher, counter)

    def build_xor_differential_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the model for the search of xor differential trails.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); if set to non-negative integer, fixes the xor trail search to a
          specific weight
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries contain name, bit_size, value (as integer) for
          the variables that need to be fixed to a certain value
          | [
          |     {
          |         'component_id': 'plaintext',
          |         'constraint_type': 'equal'/'not_equal'
          |         'bit_positions': [0, 1, 2, 3],
          |         'binary_value': [0, 0, 0, 0]
          |     }
          | ]

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: smt.build_xor_differential_trail_model()
        """
        variables = []
        self._variables_list = []
        if fixed_variables == []:
            fixed_variables = get_single_key_scenario_format_for_fixed_values(self._cipher)
        constraints = self.fix_variables_value_constraints(fixed_variables)
        component_types = (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN, WORD_OPERATION)
        operation_types = ('AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR')
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                    WORD_OPERATION == component.type and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            else:
                variables, constraints = component.smt_xor_differential_propagation_constraints(self)

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self.weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        self._variables_list.extend(self.cipher_input_variables())
        self._declarations_builder()
        self._model_constraints = \
            constants.MODEL_PREFIX + self._declarations + self._model_constraints + constants.MODEL_SUFFIX

    def find_all_xor_differential_trails_with_fixed_weight(self, fixed_weight, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Return a list of solutions  containing all the XOR differential trails having the ``fixed_weight`` weight.
        By default, the search is set in the single-key setting.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` in method
        - ``solver_name`` -- **string** (default: `Z3_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: trails = smt.find_all_xor_differential_trails_with_fixed_weight(9)
            sage: len(trails)
            2

            # related-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: trails = smt.find_all_xor_differential_trails_with_fixed_weight(2, fixed_values=[key])
            sage: len(trails)
            2
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
            operands = self.get_operands(solution)
            for component in self._cipher.get_all_components():
                bit_len = component.output_bit_size
                is_word_operation = component.type == WORD_OPERATION and component.description[0] in \
                    ('AND', 'MODADD', 'MODSUB', 'OR', 'SHIFT_BY_VARIABLE_AMOUNT')
                if component.type == SBOX or is_word_operation:
                    value_to_avoid = int(solution['components_values'][component.id]['value'], base=16)
                    operands.extend([utils.smt_not(f'{component.id}_{j}')
                                     if value_to_avoid >> (bit_len - 1 - j) & 1
                                     else f'{component.id}_{j}'
                                     for j in range(bit_len)])
            clause = utils.smt_or(operands)
            self._model_constraints = self._model_constraints[:-len(constants.MODEL_SUFFIX)] \
                                      + [utils.smt_assert(clause)] + constants.MODEL_SUFFIX
            solution = self.solve(XOR_DIFFERENTIAL, solver_name=solver_name)
            solution['building_time_seconds'] = end_building_time - start_building_time
            solution['test_name'] = "find_all_xor_differential_trails_with_fixed_weight"
        return solutions_list

    def find_all_xor_differential_trails_with_weight_at_most(self, min_weight, max_weight, fixed_values=[],
                                                             solver_name=solvers.SOLVER_DEFAULT):
        """
        Return a list of solutions.
        By default, the search is set in the single-key setting.

        The list contains all the XOR differential trails having the weight lying in the interval
        ``[min_weight, max_weight]``.

        INPUT:

        - ``min_weight`` -- **integer**; the weight from which to start the search
        - ``max_weight`` -- **integer**; the weight at which the search stops
        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Z3_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: trails = smt.find_all_xor_differential_trails_with_weight_at_most(9, 10)
            sage: len(trails)
            28

            # related-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: trails = smt.find_all_xor_differential_trails_with_weight_at_most(2, 3, fixed_values=[key])
            sage: len(trails)
            9
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
            run :py:meth:`~SmtXorDifferentialModel.find_all_xor_differential_trails_with_fixed_weight`.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Z3_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: trail = smt.find_lowest_weight_xor_differential_trail()
            sage: trail['total_weight']
            9.0

            # related-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: trail = smt.find_lowest_weight_xor_differential_trail(fixed_values=[key])
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

        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Z3_EXT`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: smt.find_one_xor_differential_trail() # random
            {'cipher_id': 'speck_p32_k64_o32_r5',
             'model_type': 'xor_differential',
             'solver_name': 'Z3_EXT',
             'solving_time_seconds': 0.05,
             'memory_megabytes': 19.28,
             ...
             'total_weight': 93,
             'building_time_seconds': 0.002946615219116211}

             # related-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: smt.find_one_xor_differential_trail(fixed_values=[key]) # random
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
        - ``solver_name`` -- **string** (default: `cryptominismt`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: trail = smt.find_one_xor_differential_trail_with_fixed_weight(3)
            sage: trail['total_weight']
            3.0

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: smt = SmtXorDifferentialModel(speck)
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=[0]*64)
            sage: trail = smt.find_one_xor_differential_trail_with_fixed_weight(3, fixed_values=[key])
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

    def get_operands(self, solution):
        operands = []
        for input_, bit_len in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            value_to_avoid = int(solution['components_values'][input_]['value'], base=16)
            operands.extend([utils.smt_not(f'{input_}_{j}')
                             if value_to_avoid >> (bit_len - 1 - j) & 1
                             else f'{input_}_{j}'
                             for j in range(bit_len)])
        return operands

    def _parse_solver_output(self, variable2value):
        out_suffix = ''
        components_solutions = self._get_cipher_inputs_components_solutions(out_suffix, variable2value)
        total_weight = 0
        for component in self._cipher.get_all_components():
            hex_value = utils.get_component_hex_value(component, out_suffix, variable2value)
            weight = self.calculate_component_weight(component, out_suffix, variable2value)
            component_solution = set_component_solution(hex_value, weight)
            components_solutions[f'{component.id}{out_suffix}'] = component_solution
            total_weight += weight

        return components_solutions, total_weight
