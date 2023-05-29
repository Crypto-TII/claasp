
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
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_xor_with_n_input_bits import \
    update_dictionary_that_contains_xor_inequalities_between_n_input_bits, \
    output_dictionary_that_contains_xor_inequalities
from claasp.cipher_modules.models.milp.milp_model import MilpModel, verbose_print
from claasp.cipher_modules.models.utils import get_bit_bindings, set_fixed_variables, integer_to_bit_list
from claasp.name_mappings import (INTERMEDIATE_OUTPUT, CONSTANT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION)


class MilpXorLinearModel(MilpModel):
    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)
        self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(cipher, '_'.join)

    def add_constraints_to_build_in_sage_milp_class(self, weight=-1, fixed_variables=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``weight`` -- **integer** (default: `-1`); the total weight. It is the negative base-2 logarithm of the total
          correlation of the trail. If negative, no constraints on the weight is added
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorLinearModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class()
            ...
            sage: mip = milp._model
            sage: mip.number_of_variables()
            1018
        """
        verbose_print("Building model in progress ...")
        self.build_xor_linear_trail_model(weight, fixed_variables)
        mip = self._model
        p = self._integer_variable
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)
        mip.add_constraint(p["probability"] == sum(
            p[self._non_linear_component_id[i] + "_probability"] for i in range(len(self._non_linear_component_id))))

    def branch_xor_linear_constraints(self):
        """
        Return a list of constraints for branch constraints.

        for a 3-way branch, it is a 1-xor:
        X + Y + Z - 2 dummy >= 0
        X + Y + Z <= 2
        dummy - X >= 0
        dummy - Y >= 0
        dummy - Z >= 0

        and more generally, for a k-way branch, it is a (k-2)-xor

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=1)
            sage: milp = MilpXorLinearModel(speck.remove_key_schedule())
            sage: milp.init_model_in_sage_milp_class()
            sage: constraints = milp.branch_xor_linear_constraints()
            sage: constraints
            [x_0 == x_1,
            x_2 == x_3,
            ...
            x_316 == x_317,
            x_318 == x_319]
        """
        x = self._binary_variable
        variables = []
        constraints = []
        for output_var, input_vars in self.bit_bindings.items():
            variables.append((f"x[{output_var}]", x[output_var]))
            variables.extend([(f"x[{var}]", x[var]) for var in input_vars])
            number_of_inputs = len(input_vars)
            if number_of_inputs == 1:
                constraints.append(x[output_var] == x[input_vars[0]])
            elif number_of_inputs == 2:
                constraints.append(x[f"{output_var}_dummy"] >= x[output_var])
                constraint = x[output_var]
                for input_var in input_vars:
                    constraints.append(x[f"{output_var}_dummy"] >= x[input_var])
                    constraint += x[input_var]
                constraints.append(2 >= constraint)
                constraints.append(constraint >= 2 * x[f"{output_var}_dummy"])
            # more than a 3-way fork as in SIMON
            else:
                self.update_xor_linear_constraints_for_more_than_two_bits(constraints, input_vars, number_of_inputs,
                                                                          output_var, x)

        return constraints

    def build_xor_linear_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the linear model.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`). By default, the weight corresponds to the negative base-2 logarithm of the
          correlation of the trail.
        - ``fixed_variables`` -- **list** (default: `[]`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: milp = MilpXorLinearModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.build_xor_linear_trail_model()
            ...
        """
        self._variables_list = []
        variables = []
        constraints = self.fix_variables_value_xor_linear_constraints(fixed_variables)
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                               SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ["AND", "MODADD", "NOT", "ROTATE", "SHIFT", "XOR", "OR", "MODSUB"]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.milp_xor_linear_mask_propagation_constraints(self)
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        constraints = self.branch_xor_linear_constraints()
        self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self.weight_xor_linear_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def exclude_variables_value_xor_linear_constraints(self, fixed_variables=[]):
        """
        Return constraints list that ensures that at least one of the specified variables is not equal to fixed values.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorLinearModel(simon)
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
            sage: constraints = milp.exclude_variables_value_xor_linear_constraints(fixed_variables)
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
                        constraints.append(x[component_id + str(bit_position) + '_o' + "_not_equal_" + str(
                            self._number_of_trails_found)] == 1 - x[component_id + '_' + str(bit_position) + '_o'])
                    else:
                        constraints.append(x[component_id + str(bit_position) + '_o' + "_not_equal_" +
                                             str(self._number_of_trails_found)] ==
                                           x[component_id + '_' + str(bit_position) + '_o'])

        var_sum = 0
        for fixed_variable in fixed_variables:
            for i in fixed_variable["bit_positions"]:
                var_sum += x[
                    fixed_variable["component_id"] + str(i) + '_o' + "_not_equal_" + str(self._number_of_trails_found)]
        constraints.append(var_sum >= 1)

        return constraints

    def find_all_xor_linear_trails_with_fixed_weight(self, fixed_weight, fixed_values=None, solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return all the XOR linear trails with weight equal to ``fixed_weight`` as a solutions list in standard format.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

        .. NOTE::

            This method should be run after you have found the solution with the
            :py:meth:`~find_lowest_weight_xor_linear_trail` method.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight found using :py:meth:`~find_lowest_weight_xor_linear_trail`
        - ``fixed_values`` -- **list** (default: `None`); each dictionary contains variables values whose output need
          to be fixed
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3)
            sage: milp = MilpXorLinearModel(speck.remove_key_schedule())
            sage: plaintext = set_fixed_variables(
            ....: component_id='plaintext', constraint_type='not equal',
            ....: bit_positions=range(8), bit_values=integer_to_bit_list(0x0, 8, 'big'))
            sage: trails = milp.find_all_xor_linear_trails_with_fixed_weight(1, fixed_values = [plaintext])  # long
            ...
            sage: len(trails) # long
            12
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        if not fixed_values:
            input_size = self._cipher.inputs_bit_size[self._cipher.inputs.index("plaintext")]
            list_of_0s = [0] * input_size
            fixed_values.append(set_fixed_variables("plaintext", "not_equal", list(range(input_size)), list_of_0s))
        self.add_constraints_to_build_in_sage_milp_class(-1, fixed_values)
        _, constraints = self.weight_xor_linear_constraints(fixed_weight)
        for constraint in constraints:
            mip.add_constraint(constraint)
        number_new_constraints = len(constraints)
        end = time.time()
        building_time = end - start

        inputs_ids = self._cipher.inputs
        list_trails = []
        looking_for_other_solutions = 1
        while looking_for_other_solutions:
            try:
                solution = self.solve("xor_linear", solver_name, external_solver_name)
                solution['building_time'] = building_time
                self._number_of_trails_found += 1
                verbose_print(f"trails found : {self._number_of_trails_found}")
                list_trails.append(solution)
                fixed_variables = []
                for index, input in enumerate(inputs_ids):
                    fixed_variable = {"component_id": input}
                    input_bit_size = self._cipher.inputs_bit_size[index]
                    fixed_variable["bit_positions"] = list(range(input_bit_size))
                    fixed_variable["constraint_type"] = "not_equal"
                    fixed_variable["bit_values"] = integer_to_bit_list(
                        BitArray(solution["components_values"][input]["value"]).int, input_bit_size, 'big')
                    fixed_variables.append(fixed_variable)

                for cipher_round in self._cipher.rounds_as_list:
                    for component in cipher_round.components:
                        fixed_variable = {"component_id": component.id}
                        output_bit_size = component.output_bit_size
                        fixed_variable["bit_positions"] = list(range(output_bit_size))
                        fixed_variable["constraint_type"] = "not_equal"
                        fixed_variable["bit_values"] = integer_to_bit_list(
                            BitArray(solution["components_values"][component.id + "_o"]["value"]).int,
                            output_bit_size, 'big')
                        fixed_variables.append(fixed_variable)

                fix_var_constraints = self.exclude_variables_value_xor_linear_constraints(fixed_variables)

                number_new_constraints += len(fix_var_constraints)
                for constraint in fix_var_constraints:
                    mip.add_constraint(constraint)
            except Exception:
                looking_for_other_solutions = 0

        number_constraints = mip.number_of_constraints()
        mip.remove_constraints(range(number_constraints - number_new_constraints, number_constraints))

        self._number_of_trails_found = 0

        return list_trails

    def find_all_xor_linear_trails_with_weight_at_most(self, min_weight, max_weight, fixed_values=[],
                                                       solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return all XOR linear trails with weight greater than ``min_weight`` and lower than or equal to ``max_weight``.

        The value returned is a list of solutions in standard format.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

        .. NOTE::

            Note that the search will start with ``min_weight`` and should end when the weight reaches a
            value greater than the maximum cipher inputs bit-size. Fix a convenient ``max_weight`` value.

        INPUT:

        - ``min_weight`` -- **integer**;  the weight found using :py:meth:`~find_lowest_weight_xor_linear_trail`
        - ``max_weight`` -- **integer**; the upper bound for the weight
        - ``fixed_values`` -- **list** (default: `[]`); each dictionary contains variables values whose output need to
          be fixed
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3)
            sage: milp = MilpXorLinearModel(speck.remove_key_schedule())
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not equal', bit_positions=range(8), bit_values=integer_to_bit_list(0x0, 8, 'big'))
            sage: trails = milp.find_all_xor_linear_trails_with_weight_at_most(0,1,[plaintext]) # long
            ...
            sage: len(trails) # long
            13
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
        list_trails = []
        for weight in range(min_weight, max_weight + 1):
            looking_for_other_solutions = 1
            _, weight_constraints = self.weight_xor_linear_constraints(weight)
            for constraint in weight_constraints:
                mip.add_constraint(constraint)
            number_new_constraints = len(weight_constraints)
            while looking_for_other_solutions:
                try:
                    solution = self.solve("xor_linear", solver_name, external_solver_name)
                    solution['building_time'] = building_time
                    self._number_of_trails_found += 1
                    verbose_print(f"trails found : {self._number_of_trails_found}")
                    list_trails.append(solution)
                    fixed_variables = self.get_fixed_variables_for_all_xor_linear_trails_with_weight_at_most(
                        fixed_values, inputs_ids, solution)

                    fix_var_constraints = self.exclude_variables_value_xor_linear_constraints(fixed_variables)
                    for constraint in fix_var_constraints:
                        mip.add_constraint(constraint)
                    number_new_constraints += len(fix_var_constraints)
                except Exception:
                    looking_for_other_solutions = 0
            number_constraints = mip.number_of_constraints()
            mip.remove_constraints(range(number_constraints - number_new_constraints, number_constraints))
        self._number_of_trails_found = 0

        return list_trails

    def find_lowest_weight_xor_linear_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return a XOR linear trail with the lowest weight in standard format, i.e. the solver solution.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        .. SEEALSO::

           :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

        verified with https://eprint.iacr.org/2019/019.pdf for Present https://eprint.iacr.org/2016/407.pdf for
        Speck and https://eprint.iacr.org/2014/747.pdf (page 17) https://eprint.iacr.org/2014/973.pdf for SIMON

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); each dictionary contains variables values whose output need to
          be fixed
        - ``solver_name`` -- **string** (default: `GLPK`); the name of the solver (if needed)

        EXAMPLES::

            # To reproduce the trail of Table 6 from https://eprint.iacr.org/2016/407.pdf run:
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=9)
            sage: milp = MilpXorLinearModel(speck.remove_key_schedule())
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=integer_to_bit_list(0x03805224, 32, 'big'))
            sage: trail = milp.find_lowest_weight_xor_linear_trail(fixed_values=[plaintext])  # doctest: +SKIP
            ...
            sage: trail["total_weight"] # doctest: +SKIP
            14.0

            # To reproduce the trail of Table 8 from https://eprint.iacr.org/2014/973.pdf run:
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=13)
            sage: milp = MilpXorLinearModel(simon.remove_key_schedule())
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=integer_to_bit_list(0x00200000, 32, 'big'))
            sage: trail = milp.find_lowest_weight_xor_linear_trail(fixed_values=[plaintext])  # doctest: +SKIP
            ...
            sage: trail["total_weight"] # doctest: +SKIP
            18.0
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
        solution = self.solve("xor_linear", solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_xor_linear_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return a XOR linear trail, not necessarily the one with the lowest weight.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed
          in standard format (see )
        - ``solver_name`` -- **string** (default: `GLPK`); the solver to call

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorLinearModel(speck.remove_key_schedule())
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=integer_to_bit_list(0x03805224, 32, 'big'))
            sage: trail = milp.find_one_xor_linear_trail(fixed_values=[plaintext]) # random
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve("xor_linear", solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_xor_linear_trail_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                    solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return one XOR linear trail with weight equal to ``fixed_weight`` as a list in standard format.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight found using :py:meth:`~find_lowest_weight_xor_linear_trail`
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
            format
        - ``solver_name`` -- **string** (default: `GLPK`); the solver to call

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorLinearModel(speck.remove_key_schedule())
            sage: trail = milp.find_one_xor_linear_trail_with_fixed_weight(6)
            ...
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(-1, fixed_values)
        _, constraints = self.weight_xor_linear_constraints(fixed_weight)
        for constraint in constraints:
            mip.add_constraint(constraint)
        end = time.time()
        building_time = end - start
        solution = self.solve("xor_linear", solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def fix_variables_value_xor_linear_constraints(self, fixed_variables=[]):
        """
        Return a list of constraints that fix the input variables to a specific value.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorLinearModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'cipher_output_1_8',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 1, 1, 0]
            ....: }]
            sage: constraints = milp.fix_variables_value_xor_linear_constraints(fixed_variables)
            sage: constraints
            [x_0 == 1,
             x_1 == 0,
             ...
             x_10 == x_11,
             1 <= x_4 + x_6 + x_8 + x_10]
        """
        x = self._binary_variable
        constraints = []
        for fixed_variable in fixed_variables:
            component_id = fixed_variable["component_id"]
            if fixed_variable["constraint_type"] == "equal":
                for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                    constraints.append(x[component_id + '_' + str(bit_position) + '_o']
                                       == fixed_variable["bit_values"][index])
            else:
                for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                    if fixed_variable["bit_values"][index]:
                        constraints.append(
                            x[component_id + str(bit_position) + '_o' + "_not_equal_" +
                              str(self._number_of_trails_found)] ==
                            1 - x[component_id + '_' + str(bit_position) + '_o'])
                    else:
                        constraints.append(
                            x[component_id + str(bit_position) + '_o' + "_not_equal_" +
                              str(self._number_of_trails_found)] == x[component_id + '_' + str(bit_position) + '_o'])
                constraints.append(sum(
                    x[component_id + str(i) + '_o' + "_not_equal_" + str(self._number_of_trails_found)] for i in
                    fixed_variable["bit_positions"]) >= 1)

        return constraints

    def get_fixed_variables_for_all_xor_linear_trails_with_weight_at_most(self, fixed_values, inputs_ids, solution):
        fixed_variables = []
        for index, input in enumerate(inputs_ids):
            input_bit_size = self._cipher.inputs_bit_size[index]
            fixed_variable = {"component_id": input,
                              "bit_positions": list(range(input_bit_size)),
                              "constraint_type": "not_equal",
                              "bit_values": integer_to_bit_list(
                                  BitArray(solution["components_values"][input]["value"]).int,
                                  input_bit_size, 'big')}

            fixed_variables += [fixed_variable for dictio in fixed_values
                                if dictio["component_id"] == input and
                                dictio["bit_values"] != fixed_variable["bit_values"]]
        for component in self._cipher.get_all_components():
            output_bit_size = component.output_bit_size
            fixed_variable = {"component_id": component.id,
                              "bit_positions": list(range(output_bit_size)),
                              "constraint_type": "not_equal",
                              "bit_values": integer_to_bit_list(
                                  BitArray(solution["components_values"][component.id + "_o"]["value"]).int,
                                  output_bit_size, 'big')}
            fixed_variables.append(fixed_variable)

        return fixed_variables

    def update_xor_linear_constraints_for_more_than_two_bits(self, constraints, input_vars,
                                                             number_of_inputs, output_var, x):
        update_dictionary_that_contains_xor_inequalities_between_n_input_bits(number_of_inputs)
        dict_inequalities = output_dictionary_that_contains_xor_inequalities()
        inequalities = dict_inequalities[number_of_inputs]
        for ineq in inequalities:
            constraint = 0
            last_char = None
            for input in range(number_of_inputs):
                char = ineq[input]
                if char == "1":
                    constraint += 1 - x[input_vars[input]]
                    last_char = ineq[number_of_inputs]
                elif char == "0":
                    constraint += x[input_vars[input]]
                    last_char = ineq[number_of_inputs]
            if last_char == "1":
                constraint += 1 - x[output_var]
                constraints.append(constraint >= 1)
            elif last_char == "0":
                constraint += x[output_var]
                constraints.append(constraint >= 1)

    def weight_xor_linear_constraints(self, weight):
        """
        Return a list of variables and a list of constraints that fix the total weight to a specific value.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        INPUT:

        - ``weight`` -- **integer**; the total weight. By default, it is the negative base-2 logarithm of the total
          correlation of the trail.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpXorLinearModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = milp.weight_xor_linear_constraints(10)
            sage: variables
            [('p[probability]', x_0)]
            sage: constraints
            [x_0 == 100]
        """
        return self.weight_constraints(weight)
