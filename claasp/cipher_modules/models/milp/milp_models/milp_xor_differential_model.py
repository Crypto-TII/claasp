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
import os
import sys
import time

import numpy as np
from bitstring import BitArray

from claasp.cipher_modules.models.milp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_XOR_DIFFERENTIAL, MILP_PROBABILITY_SUFFIX, \
    MILP_BUILDING_MESSAGE, MILP_XOR_DIFFERENTIAL_OBJECTIVE, MILP_DEFAULT_WEIGHT_PRECISION
from claasp.cipher_modules.models.milp.utils.utils import _string_to_hex, _get_variables_values_as_string, \
    _filter_fixed_variables, _set_weight_precision
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_component_solution, \
    get_single_key_scenario_format_for_fixed_values
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN, INPUT_KEY)


class MilpXorDifferentialModel(MilpModel):

    def __init__(self, cipher, n_window_heuristic=None, verbose=False):
        super().__init__(cipher, n_window_heuristic, verbose)
        self._weight_precision = MILP_DEFAULT_WEIGHT_PRECISION
        self._has_non_integer_weight = False

    def add_constraints_to_build_in_sage_milp_class(self, weight=-1, weight_precision=MILP_DEFAULT_WEIGHT_PRECISION,
                                                    fixed_variables=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``weight`` -- **integer** (default: `-1`); the total weight. If negative, no constraints on the weight is
          added
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class()
            ...
            sage: mip = milp._model
            sage: mip.number_of_variables()
            468
        """
        self._verbose_print(MILP_BUILDING_MESSAGE)
        self._weight_precision = weight_precision
        self.build_xor_differential_trail_model(weight, fixed_variables)
        mip = self._model
        p = self._integer_variable
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)
        mip.add_constraint(p[MILP_XOR_DIFFERENTIAL_OBJECTIVE] == sum(
            p[self._non_linear_component_id[i] + "_probability"] for i in range(len(self._non_linear_component_id))))

    def build_xor_differential_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the model for the search of XOR differential trails.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight
        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.build_xor_differential_trail_model()
            ...
        """
        variables = []
        self._variables_list = []
        if fixed_variables == []:
            fixed_variables = get_single_key_scenario_format_for_fixed_values(self._cipher)
        constraints = self.fix_variables_value_constraints(fixed_variables)
        component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN, WORD_OPERATION]
        operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                    WORD_OPERATION == component.type and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            else:
                variables, constraints = component.milp_xor_differential_propagation_constraints(self)

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self.weight_constraints(weight, self._weight_precision)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def find_all_xor_differential_trails_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                           weight_precision=MILP_DEFAULT_WEIGHT_PRECISION,
                                                           solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return all the XOR differential trails with weight equal to ``fixed_weight`` as a list in standard format.
        By default, the search is set in the single-key setting.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

        .. NOTE::

            This method should be run after you have found the solution with the
            :py:meth:`~find_lowest_weight_xor_differential_trail` method.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight found using :py:meth:`~find_lowest_weight_xor_differential_trail`
        - ``fixed_values`` -- **list** (default: `[]`); each dictionary contains variables values whose output
          need to be fixed
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trails = milp.find_all_xor_differential_trails_with_fixed_weight(9) # long
            ...
            sage: len(trails)
            2

            # related-key setting
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(64)), [0] * 64)
            sage: trails = milp.find_all_xor_differential_trails_with_fixed_weight(2, fixed_values=[key]) # long
            ...
            sage: len(trails)
            2
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, weight_precision, fixed_values)
        number_new_constraints = 0
        _, constraints = self.weight_constraints(fixed_weight, weight_precision)
        for constraint in constraints:
            mip.add_constraint(constraint)
        number_new_constraints += len(constraints)

        end = time.time()
        building_time = end - start

        if fixed_values == []:
            fixed_values = get_single_key_scenario_format_for_fixed_values(self._cipher)
        if INPUT_KEY in self._cipher.inputs and self.is_single_key(fixed_values):
            inputs_ids = [i for i in self._cipher.inputs if INPUT_KEY not in i]
        else:
            inputs_ids = self._cipher.inputs

        list_trails = []
        looking_for_other_solutions = 1
        while looking_for_other_solutions:
            try:
                f = open(os.devnull, 'w')
                sys.stdout = f
                solution = self.solve(MILP_XOR_DIFFERENTIAL, solver_name, external_solver_name)
                sys.stdout = sys.__stdout__
                solution['building_time'] = building_time
                solution['test_name'] = "find_all_xor_differential_trails_with_fixed_weight"
                self._number_of_trails_found += 1
                self._verbose_print(f"trails found : {self._number_of_trails_found}")
                list_trails.append(solution)
                fixed_variables = self._get_fixed_variables_from_solution(fixed_values, inputs_ids, solution)

                fix_var_constraints = self.exclude_variables_value_constraints(fixed_variables)
                number_new_constraints += len(fix_var_constraints)
                for constraint in fix_var_constraints:
                    mip.add_constraint(constraint)
            except Exception:
                looking_for_other_solutions = 0
            finally:
                sys.stdout = sys.__stdout__

        number_constraints = mip.number_of_constraints()
        mip.remove_constraints(range(number_constraints - number_new_constraints, number_constraints))

        self._number_of_trails_found = 0

        return [trail for trail in list_trails if trail['status'] == 'SATISFIABLE']

    def exclude_variables_value_constraints(self, fixed_variables=[]):
        """
        Return constraints list that ensures that at least one of the specified variables is not equal to fixed values.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'cipher_output_2_12',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 1, 1, 0]
            ....: }]
            sage: constraints = milp.exclude_variables_value_constraints(fixed_variables)
            sage: constraints
            [x_0 == 1 - x_1,
             x_2 == x_3,
             x_4 == 1 - x_5,
             x_6 == 1 - x_7,
             x_8 == 1 - x_9,
             x_10 == 1 - x_11,
             x_12 == 1 - x_13,
             x_14 == x_15,
             1 <= x_0 + x_2 + x_4 + x_6 + x_8 + x_10 + x_12 + x_14]
        """
        x = self._binary_variable
        constraints = []
        for fixed_variable in fixed_variables:
            component_id = fixed_variable["component_id"]
            if fixed_variable["constraint_type"] == "not_equal":
                for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                    if fixed_variable["bit_values"][index]:
                        constraints.append(x[component_id +
                                             str(bit_position) +
                                             "_not_equal_" +
                                             str(self._number_of_trails_found)] == 1 -
                                           x[component_id +
                                             '_' +
                                             str(bit_position)])
                    else:
                        constraints.append(x[component_id +
                                             str(bit_position) +
                                             "_not_equal_" +
                                             str(self._number_of_trails_found)] == x[component_id +
                                                                                     '_' +
                                                                                     str(bit_position)])

        var_sum = 0
        for fixed_variable in fixed_variables:
            for i in fixed_variable["bit_positions"]:
                var_sum += x[fixed_variable["component_id"] +
                             str(i) + "_not_equal_" + str(self._number_of_trails_found)]
        constraints.append(var_sum >= 1)

        return constraints

    def is_single_key(self, fixed_values):
        """
        Return True if key is fixed to 0, False otherwise.

        INPUT:

        - ``fixed_values`` -- **list**; dictionaries containing each dict contains variables values whose output need to
          be fixed

        EXAMPLES::
            from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: milp.is_single_key(speck)
            True
        """
        cipher_inputs = self._cipher.inputs
        cipher_inputs_bit_size = self._cipher.inputs_bit_size
        for fixed_input in [value for value in fixed_values if value['component_id'] in cipher_inputs]:
            input_size = cipher_inputs_bit_size[cipher_inputs.index(fixed_input['component_id'])]
            if fixed_input['component_id'] == 'key' and fixed_input['constraint_type'] == 'equal' \
                    and list(fixed_input['bit_positions']) == list(range(input_size)) \
                    and all(v == 0 for v in fixed_input['bit_values']):
                return True

        return False

    def find_all_xor_differential_trails_with_weight_at_most(self, min_weight, max_weight,
                                                             fixed_values=[], weight_precision=MILP_DEFAULT_WEIGHT_PRECISION,
                                                             solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return all XOR differential trails with weight greater than ``min_weight`` and lower/equal to ``max_weight``.
        By default, the search is set in the single-key setting.
        The value returned is a list of solutions in standard format.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`.

        .. NOTE::

            Note that the search will start with ``min_weight`` and should end when the weight reaches a
            value greater than the maximum cipher inputs bit-size. Fix a convenient ``max_weight`` value.

        INPUT:

        - ``min_weight`` -- **integer**;  the weight found using :py:meth:`~find_lowest_weight_xor_differential_trail`.
        - ``max_weight`` -- **integer**; the upper bound for the weight.
        - ``fixed_values`` -- **list** (default: `[]`); each dictionary contains variables values whose output need to
          be fixed
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLES::

            # single-key setting
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trails = milp.find_all_xor_differential_trails_with_weight_at_most(9, 10) # long
            ...
            sage: len(trails)
            28

            # related-key setting
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(64)), [0] * 64)
            sage: trails = milp.find_all_xor_differential_trails_with_weight_at_most(2, 3, fixed_values=[key]) # long
            ...
            sage: len(trails)
            9
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, weight_precision, fixed_values)
        end = time.time()
        building_time = end - start

        if fixed_values == []:
            fixed_values = get_single_key_scenario_format_for_fixed_values(self._cipher)
        inputs_ids = self._cipher.inputs
        if INPUT_KEY in self._cipher.inputs and self.is_single_key(fixed_values):
            inputs_ids = [i for i in self._cipher.inputs if INPUT_KEY not in i]

        list_trails = []
        precision = _set_weight_precision(self, "differential")
        for weight in np.arange(min_weight, max_weight + 1, precision):
            looking_for_other_solutions = 1
            _, weight_constraints = self.weight_constraints(weight, weight_precision)
            for constraint in weight_constraints:
                mip.add_constraint(constraint)
            number_new_constraints = len(weight_constraints)
            while looking_for_other_solutions:
                try:
                    f = open(os.devnull, 'w')
                    sys.stdout = f
                    solution = self.solve(MILP_XOR_DIFFERENTIAL, solver_name, external_solver_name)
                    sys.stdout = sys.__stdout__
                    solution['building_time'] = building_time
                    solution['test_name'] = "find_all_xor_differential_trails_with_weight_at_most"
                    self._number_of_trails_found += 1
                    self._verbose_print(f"trails found : {self._number_of_trails_found}")
                    list_trails.append(solution)
                    fixed_variables = self._get_fixed_variables_from_solution(fixed_values, inputs_ids, solution)

                    fix_var_constraints = self.exclude_variables_value_constraints(fixed_variables)
                    for constraint in fix_var_constraints:
                        mip.add_constraint(constraint)
                    number_new_constraints += len(fix_var_constraints)
                except Exception:
                    looking_for_other_solutions = 0
                finally:
                    sys.stdout = sys.__stdout__
            number_constraints = mip.number_of_constraints()
            mip.remove_constraints(range(number_constraints - number_new_constraints, number_constraints))
        self._number_of_trails_found = 0

        return [trail for trail in list_trails if trail['status'] == 'SATISFIABLE']

    def find_lowest_weight_xor_differential_trail(self, fixed_values=[], weight_precision=MILP_DEFAULT_WEIGHT_PRECISION,
                                                  solver_name=SOLVER_DEFAULT, external_solver_name=False):
        """
        Return a XOR differential trail with the lowest weight in standard format, i.e. the solver solution.
        By default, the search is set in the single-key setting.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); each dictionary contains variables values whose output need
          to be fixed
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLES::

            # single-key setting
            from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trail = milp.find_lowest_weight_xor_differential_trail()
            ...
            sage: trail["total_weight"]
            9.0

            # related-key setting
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(64)), [0] * 64)
            sage: trail = milp.find_lowest_weight_xor_differential_trail(fixed_values=[key])
            ...
            sage: trail["total_weight"]
            1.0
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        p = self._integer_variable
        mip.set_objective(p[MILP_XOR_DIFFERENTIAL_OBJECTIVE])

        self.add_constraints_to_build_in_sage_milp_class(-1, weight_precision, fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_XOR_DIFFERENTIAL, solver_name, external_solver_name)
        solution['building_time'] = building_time
        solution['test_name'] = "find_lowest_weight_xor_differential_trail"

        return solution

    def find_one_xor_differential_trail(self, fixed_values=[], weight_precision=MILP_DEFAULT_WEIGHT_PRECISION, solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return a XOR differential trail, not necessarily the one with the lowest weight.
        By default, the search is set in the single-key setting.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
            format
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.
        - ``solver_name`` -- **string** (default: `GLPK`); the solver to call
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            # single-key setting
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trail = milp.find_one_xor_differential_trail() # random

            # related-key setting
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(64)), [0] * 64)
            sage: trail = milp.find_one_xor_differential_trail(fixed_values=[key]) # random
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, weight_precision, fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_XOR_DIFFERENTIAL, solver_name, external_solver_name)
        solution['building_time'] = building_time
        solution['test_name'] = "find_one_xor_differential_trail"

        return solution

    def find_one_xor_differential_trail_with_fixed_weight(self, fixed_weight, fixed_values=[], weight_precision=MILP_DEFAULT_WEIGHT_PRECISION,
                                                          solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return one XOR differential trail with weight equal to ``fixed_weight`` as a list in standard format.
        By default, the search is set in the single-key setting.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight found using :py:meth:`~find_lowest_weight_xor_differential_trail`
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
            format
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.
        - ``solver_name`` -- **string** (default: `GLPK`); the solver to call
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            # single-key setting
            from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trail = milp.find_one_xor_differential_trail_with_fixed_weight(3) # random
            sage: trail['total_weight']
            3.0

            # related-key setting
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(64)), [0] * 64)
            sage: trail = milp.find_one_xor_differential_trail_with_fixed_weight(3, fixed_values=[key]) # random
            sage: trail['total_weight']
            3.0
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, weight_precision, fixed_values)
        _, constraints = self.weight_constraints(fixed_weight, weight_precision)
        for constraint in constraints:
            mip.add_constraint(constraint)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_XOR_DIFFERENTIAL, solver_name, external_solver_name)
        solution['building_time'] = building_time
        solution['test_name'] = "find_one_xor_differential_trail_with_fixed_weight"

        return solution

    def _get_fixed_variables_from_solution(self, fixed_values, inputs_ids, solution):
        fixed_variables = []
        for input in inputs_ids:
            input_bit_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(input)]
            fixed_variable = {"component_id": input,
                              "bit_positions": list(range(input_bit_size)),
                              "constraint_type": "not_equal",
                              "bit_values": (integer_to_bit_list(
                                  BitArray(solution["components_values"][input]["value"]).int,
                                  input_bit_size, 'big'))}
            _filter_fixed_variables(fixed_values, fixed_variable, input)
            fixed_variables.append(fixed_variable)

        for component in self._cipher.get_all_components():
            output_bit_size = component.output_bit_size
            fixed_variable = {"component_id": component.id,
                              "bit_positions": list(range(output_bit_size)),
                              "constraint_type": "not_equal",
                              "bit_values": integer_to_bit_list(
                                BitArray(solution["components_values"][component.id]["value"]).int,
                            output_bit_size, 'big')}
            _filter_fixed_variables(fixed_values, fixed_variable, component.id)
            fixed_variables.append(fixed_variable)

        return fixed_variables

    def _get_component_values(self, objective_variables, components_variables):
        components_values = {}
        list_component_ids = self._cipher.inputs + self._cipher.get_all_components_ids()
        for component_id in list_component_ids:
            dict_tmp = self._get_component_value_weight(component_id,
                                                        objective_variables, components_variables)
            components_values[component_id] = dict_tmp
        return components_values

    def _parse_solver_output(self):
        mip = self._model
        objective_variables = mip.get_values(self._integer_variable)
        objective_value = objective_variables[MILP_XOR_DIFFERENTIAL_OBJECTIVE] / float(10 ** self._weight_precision)
        components_variables = mip.get_values(self._binary_variable)
        components_values = self._get_component_values(objective_variables, components_variables)

        return objective_value, components_values

    def _get_component_value_weight(self, component_id, probability_variables, components_variables):

        if component_id in self._cipher.inputs:
            output_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(component_id)]
        else:
            component = self._cipher.get_component_from_id(component_id)
            output_size = component.output_bit_size
        suffix_dict = {"": output_size}
        final_output = self._get_final_output(component_id, components_variables, probability_variables, suffix_dict)
        if len(final_output) == 1:
            final_output = final_output[0]

        return final_output

    def _get_final_output(self, component_id, components_variables, probability_variables,
                         suffix_dict):
        final_output = []
        for suffix in suffix_dict.keys():
            diff_str = _get_variables_values_as_string(component_id, components_variables, suffix, suffix_dict[suffix])
            difference = _string_to_hex(diff_str)
            weight = 0
            if component_id + MILP_PROBABILITY_SUFFIX in probability_variables:
                weight = probability_variables[component_id + MILP_PROBABILITY_SUFFIX] / float(10 ** self._weight_precision)
            final_output.append(set_component_solution(value=difference, weight=weight))
        return final_output

    @property
    def weight_precision(self):
        return self._weight_precision
