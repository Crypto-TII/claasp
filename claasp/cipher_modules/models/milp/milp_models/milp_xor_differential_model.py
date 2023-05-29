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

from bitstring import BitArray

from claasp.cipher_modules.models.milp.utils.config import SOLVER_DEFAULT
from claasp.cipher_modules.models.milp.milp_model import MilpModel, verbose_print
from claasp.cipher_modules.models.utils import integer_to_bit_list
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)


class MilpXorDifferentialModel(MilpModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)

    def add_constraints_to_build_in_sage_milp_class(self, weight=-1, fixed_variables=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``weight`` -- **integer** (default: `-1`); the total weight. If negative, no constraints on the weight is
          added
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
        verbose_print("Building model in progress ...")
        self.build_xor_differential_trail_model(weight, fixed_variables)
        mip = self._model
        p = self._integer_variable
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)
        mip.add_constraint(p["probability"] == sum(
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
            variables, constraints = self.weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def find_all_xor_differential_trails_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                           solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return all the XOR differential trails with weight equal to ``fixed_weight`` as a list in standard format.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

        .. NOTE::

            This method should be run after you have found the solution with the
            :py:meth:`~find_lowest_weight_xor_differential_trail` method.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight found using :py:meth:`~find_lowest_weight_xor_differential_trail`
        - ``fixed_values`` -- **list** (default: `[]`); each dictionary contains variables values whose output
          need to be fixed
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)

        EXAMPLES::
            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trails = milp.find_all_xor_differential_trails_with_fixed_weight(1, get_single_key_scenario_format_for_fixed_values(speck)) # long
            ...
            sage: len(trails) # long
            6
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, fixed_values)
        number_new_constraints = 0
        variables, constraints = self.weight_constraints(fixed_weight)
        for constraint in constraints:
            mip.add_constraint(constraint)
        number_new_constraints += len(constraints)

        end = time.time()
        building_time = end - start

        if self.is_single_key(fixed_values):
            inputs_ids = [i for i in self._cipher.inputs if "key" not in i]
        else:
            inputs_ids = self._cipher.inputs

        list_trails = []
        looking_for_other_solutions = 1
        while looking_for_other_solutions:
            try:
                solution = self.solve("xor_differential", solver_name, external_solver_name)
                solution['building_time'] = building_time
                self._number_of_trails_found += 1
                verbose_print(f"trails found : {self._number_of_trails_found}")
                list_trails.append(solution)
                fixed_variables = []
                for index, input in enumerate(inputs_ids):
                    fixed_variable = {}
                    fixed_variable["component_id"] = input
                    input_bit_size = self._cipher.inputs_bit_size[index]
                    fixed_variable["bit_positions"] = list(range(input_bit_size))
                    fixed_variable["constraint_type"] = "not_equal"
                    fixed_variable["bit_values"] = integer_to_bit_list(
                        BitArray(solution["components_values"][input]["value"]).int, input_bit_size, 'big')
                    fixed_variables.append(fixed_variable)

                for cipher_round in self._cipher.rounds_as_list:
                    for component in cipher_round.components:
                        fixed_variable = {}
                        fixed_variable["component_id"] = component.id
                        output_bit_size = component.output_bit_size
                        fixed_variable["bit_positions"] = list(range(output_bit_size))
                        fixed_variable["constraint_type"] = "not_equal"
                        fixed_variable["bit_values"] = integer_to_bit_list(
                            BitArray(solution["components_values"][component.id]["value"]).int, output_bit_size, 'big')
                        fixed_variables.append(fixed_variable)

                fix_var_constraints = self.exclude_variables_value_constraints(fixed_variables)
                number_new_constraints += len(fix_var_constraints)
                for constraint in fix_var_constraints:
                    mip.add_constraint(constraint)
            except Exception:
                looking_for_other_solutions = 0

        number_constraints = mip.number_of_constraints()
        mip.remove_constraints(range(number_constraints - number_new_constraints, number_constraints))

        self._number_of_trails_found = 0

        return list_trails

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
            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: milp.is_single_key(get_single_key_scenario_format_for_fixed_values(speck))
            True
        """
        cipher_inputs = self._cipher.inputs
        cipher_inputs_bit_size = self._cipher.inputs_bit_size
        for fixed_input in fixed_values:
            input_size = cipher_inputs_bit_size[cipher_inputs.index(fixed_input['component_id'])]
            if fixed_input['component_id'] == 'key' and fixed_input['constraint_type'] == 'equal' \
                    and fixed_input['bit_positions'] == list(range(input_size)) \
                    and all(v == 0 for v in fixed_input['bit_values']):
                return True

        return False

    def find_all_xor_differential_trails_with_weight_at_most(self, min_weight, max_weight,
                                                             fixed_values=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return all XOR differential trails with weight greater than ``min_weight`` and lower/equal to ``max_weight``.

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
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trails = milp.find_all_xor_differential_trails_with_weight_at_most(0, 1, get_single_key_scenario_format_for_fixed_values(speck)) # long
            ...
            sage: len(trails) # long
            7
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, fixed_values)
        end = time.time()
        building_time = end - start
        inputs_ids = self._cipher.inputs
        if self.is_single_key(fixed_values):
            inputs_ids = [i for i in self._cipher.inputs if "key" not in i]

        list_trails = []
        for weight in range(min_weight, max_weight + 1):
            looking_for_other_solutions = 1
            variables, weight_constraints = self.weight_constraints(weight)
            for constraint in weight_constraints:
                mip.add_constraint(constraint)
            number_new_constraints = len(weight_constraints)
            while looking_for_other_solutions:
                try:
                    solution = self.solve("xor_differential", solver_name, external_solver_name)
                    solution['building_time'] = building_time
                    self._number_of_trails_found += 1
                    verbose_print(f"trails found : {self._number_of_trails_found}")
                    list_trails.append(solution)
                    fixed_variables = self.get_fixed_variables_for_all_xor_differential_trails_with_weight_at_most(
                        fixed_values, inputs_ids, solution)

                    fix_var_constraints = self.exclude_variables_value_constraints(fixed_variables)
                    for constraint in fix_var_constraints:
                        mip.add_constraint(constraint)
                    number_new_constraints += len(fix_var_constraints)
                except Exception:
                    looking_for_other_solutions = 0
            number_constraints = mip.number_of_constraints()
            mip.remove_constraints(range(number_constraints - number_new_constraints, number_constraints))
        self._number_of_trails_found = 0

        return list_trails

    def find_lowest_weight_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT,
                                                  external_solver_name=False):
        """
        Return a XOR differential trail with the lowest weight in standard format, i.e. the solver solution.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); each dictionary contains variables values whose output need
          to be fixed
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trail = milp.find_lowest_weight_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(speck))
            ...
            sage: trail["total_weight"]
            1.0
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        p = self._integer_variable
        mip.set_objective(p["probability"])

        self.add_constraints_to_build_in_sage_milp_class(-1, fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve("xor_differential", solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return a XOR differential trail, not necessary the one with the lowest weight.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
            format
        - ``solver_name`` -- **string** (default: `GLPK`); the solver to call

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trail = milp.find_one_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(speck)) # random
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve("xor_differential", solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_xor_differential_trail_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                          solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return one XOR differential trail with weight equal to ``fixed_weight`` as a list in standard format.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight found using :py:meth:`~find_lowest_weight_xor_differential_trail`
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
            format
        - ``solver_name`` -- **string** (default: `GLPK`); the solver to call

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorDifferentialModel(speck)
            sage: trail = milp.find_one_xor_differential_trail_with_fixed_weight(5, get_single_key_scenario_format_for_fixed_values(speck))
            ...
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, fixed_values)
        variables, constraints = self.weight_constraints(fixed_weight)
        for constraint in constraints:
            mip.add_constraint(constraint)
        end = time.time()
        building_time = end - start
        solution = self.solve("xor_differential", solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def get_fixed_variables_for_all_xor_differential_trails_with_weight_at_most(self, fixed_values, inputs_ids,
                                                                                solution):
        fixed_variables = []
        for index, input in enumerate(inputs_ids):
            input_bit_size = self._cipher.inputs_bit_size[index]
            fixed_variable = {"component_id": input,
                              "bit_positions": list(range(input_bit_size)),
                              "constraint_type": "not_equal",
                              "bit_values": (integer_to_bit_list(
                                  BitArray(solution["components_values"][input]["value"]).int,
                                  input_bit_size, 'big'))}

            fixed_variables += [fixed_variable for dictio in fixed_values
                                if dictio["component_id"] == input and
                                dictio["bit_values"] != fixed_variable["bit_values"]]

            for component in self._cipher.get_all_components():
                output_bit_size = component.output_bit_size
                fixed_variable = {"component_id": component.id,
                                  "bit_positions": list(range(output_bit_size)),
                                  "constraint_type": "not_equal",
                                  "bit_values": integer_to_bit_list(
                                      BitArray(solution["components_values"][component.id]["value"]).int,
                                      output_bit_size, 'big')}
                fixed_variables.append(fixed_variable)

        return fixed_variables
