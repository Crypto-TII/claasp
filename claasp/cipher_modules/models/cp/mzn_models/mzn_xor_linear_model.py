
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


import math
import time as tm

from sage.crypto.sbox import SBox

from claasp.cipher_modules.models.cp.mzn_model import MznModel, solve_satisfy, constraint_type_error
from claasp.cipher_modules.models.utils import get_bit_bindings, \
    get_single_key_scenario_format_for_fixed_values
from claasp.name_mappings import INTERMEDIATE_OUTPUT, XOR_LINEAR, CONSTANT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, \
    MIX_COLUMN, WORD_OPERATION, INPUT_KEY
from claasp.cipher_modules.models.cp.solvers import SOLVER_DEFAULT


class MznXorLinearModel(MznModel):

    def __init__(self, cipher):
        super().__init__(cipher)
        format_func = lambda record: f'{record[0]}_{record[2]}[{record[1]}]'
        self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(
                cipher, format_func)

    def and_xor_linear_probability_lat(self, numadd):
        """
        Return the lat of the and operation.

        INPUT:

        - ``numadd`` -- **integer**; the number of addenda

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher()
            sage: cp = MznXorLinearModel(simon)
            sage: cp.and_xor_linear_probability_lat(2)
            [2, 1, 0, 1, 0, 1, 0, -1]
        """
        lat = []
        for full_mask in range(2 ** (numadd + 1)):
            num_of_matches = 0
            for values in range(2 ** numadd):
                full_values = values << 1
                bit_of_values = (values >> i & 1 for i in range(numadd))
                full_values ^= 0 not in bit_of_values
                equation = full_values & full_mask
                addenda = (equation >> i & 1 for i in range(numadd + 1))
                num_of_matches += (sum(addenda) % 2 == 0)
            lat.append(num_of_matches - (2 ** (numadd - 1)))

        return lat

    def branch_xor_linear_constraints(self):
        """
        Return a list of Cp constraints for the branching of the linear model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: cp.branch_xor_linear_constraints()
            ['constraint plaintext_o[0] = rot_0_0_i[0];',
             'constraint plaintext_o[1] = rot_0_0_i[1];',
             'constraint plaintext_o[2] = rot_0_0_i[2];',
             ...
             'constraint xor_3_10_o[13] = cipher_output_3_12_i[29];',
             'constraint xor_3_10_o[14] = cipher_output_3_12_i[30];',
             'constraint xor_3_10_o[15] = cipher_output_3_12_i[31];']
        """
        cp_constraints = []
        for output_bit_id, input_bit_ids in self.bit_bindings.items():
            # no fork
            if len(input_bit_ids) == 1:
                cp_constraints.append(f'constraint {output_bit_id} = {input_bit_ids[0]};')
            # fork
            else:
                operation = f'({" + ".join(input_bit_ids)}) mod 2;'
                cp_constraints.append(f'constraint {output_bit_id} = {operation}')

        return cp_constraints

    def build_xor_linear_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the Cp model for the search of XOR linear trails.

        INPUT:

        - ``weight`` -- **integer** (default: `1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: speck = speck.remove_key_schedule()
            sage: cp = MznXorLinearModel(speck)
            sage: fixed_variables = [set_fixed_variables('plaintext', 'not_equal', list(range(32)), integer_to_bit_list(0, 32, 'little'))]
            sage: cp.build_xor_linear_trail_model(-1, fixed_variables)
        """
        self.initialise_model()
        self.sbox_mant = []
        self.c = 0
        self._variables_list = []
        self.component_and_probability = {}
        self._variables_list = []
        variables = []
        if INPUT_KEY not in [variable["component_id"] for variable in fixed_variables]:
            cipher_without_key_schedule = self._cipher.remove_key_schedule()
            self._cipher = cipher_without_key_schedule
            self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(
                self._cipher, lambda record: f'{record[0]}_{record[2]}[{record[1]}]')
        if fixed_variables == []:
            fixed_variables = get_single_key_scenario_format_for_fixed_values(self._cipher)
        constraints = self.fix_variables_value_xor_linear_constraints(fixed_variables)
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                               SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ["AND", "MODADD", "NOT", "ROTATE", "SHIFT", "XOR", "OR", "MODSUB"]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.cp_xor_linear_mask_propagation_constraints(self)
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

        variables, constraints = self.input_xor_linear_constraints()
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        self._model_constraints.extend(self.final_xor_linear_constraints(weight))
        self._model_constraints = self._model_prefix + self._variables_list + self._model_constraints

    def final_xor_linear_constraints(self, weight):
        """
        Return a list of Cp constraints for the outputs of the cipher and solving indications for single step or second step model for xor linear model.

        INPUT:

        - ``weight`` -- **integer**; a specific weight. If set to non-negative integer, fixes the XOR trail weight

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: speck = speck.remove_key_schedule()
            sage: cp = MznXorLinearModel(speck)
            sage: fixed_variables = [set_fixed_variables('plaintext', 'not_equal', list(range(32)), integer_to_bit_list(0, 32, 'little'))]
            sage: cp.build_xor_linear_trail_model(-1, fixed_variables)
            sage: cp.final_xor_linear_constraints(-1)[:-1]
            ['solve:: int_search(p, smallest, indomain_min, complete) minimize sum(p);']
        """
        cipher_inputs = self._cipher.inputs
        cp_constraints = ['solve:: int_search(p, smallest, indomain_min, complete) minimize sum(p);'
                          if weight == -1 else solve_satisfy]
        new_constraint = 'output['
        for i, element in enumerate(cipher_inputs):
            new_constraint += f'\"{element} = \"++ show({element}_o) ++ \"\\n\" ++'
        for component in self._cipher.get_all_components():
            if SBOX in component.type:
                new_constraint += f'\"{component.id}_i = \"++ show({component.id}_i)++ \"\\n\" ++ ' \
                                  f'\"{component.id}_o = \"++ show({component.id}_o)++ \"\\n\" ++ ' \
                                  f'show(p[{self.component_and_probability[component.id]}]) ++ \"\\n\" ++'
            elif CIPHER_OUTPUT in component.type:
                new_constraint += f'\"{component.id}_o= \"++ ' \
                                  f'show({component.id}_i)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
            elif WORD_OPERATION in component.type:
                new_constraint = self.get_word_operation_final_xor_linear_constraints(component, new_constraint)
            else:
                new_constraint += f'\"{component.id}_i = \"++ show({component.id}_o)++ \"\\n\" ++ ' \
                                  f'\"{component.id}_o = \"++ show({component.id}_o)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'

        new_constraint += '\"Trail weight = \" ++ show(weight)];'
        cp_constraints.append(new_constraint)

        return cp_constraints

    def find_all_xor_linear_trails_with_fixed_weight(self, fixed_weight, fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = False):
        """
        Return a list of solutions containing all the linear trails having the ``fixed_weight`` weight of correlation.
        By default, the search removes the key schedule, if any.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3)
            sage: cp = MznXorLinearModel(speck)
            sage: trails = cp.find_all_xor_linear_trails_with_fixed_weight(1) # long
            sage: len(trails)
            12

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(16)), [0] * 16)
            sage: trails = cp.find_all_xor_linear_trails_with_fixed_weight(2, fixed_values=[key])
            sage: len(trails)
            8
        """
        start = tm.time()
        self.build_xor_linear_trail_model(fixed_weight, fixed_values)
        end = tm.time()
        build_time = end - start
        if solve_with_API:
            solutions = self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, all_solutions_ = True)
        else:
            solutions = self.solve(XOR_LINEAR, solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, all_solutions_ = True, solve_external = solve_external)
            for solution in solutions:
                solution['building_time_seconds'] = build_time
                solution['test_name'] = "find_all_xor_linear_trails_with_fixed_weight"
        return solutions

    def find_all_xor_linear_trails_with_weight_at_most(self, min_weight, max_weight=64,
                                                       fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = False):
        """
        Return a list of solutions containing all the linear trails having the weight of correlation lying in the interval ``[min_weight, max_weight]``.
        By default, the search removes the key schedule, if any.

        INPUT:

        - ``min_weight`` -- **integer**; the weight from which to start the search
        - ``max_weight`` -- **integer** (default: `64`); the weight at which the search stops
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3)
            sage: cp = MznXorLinearModel(speck)
            sage: trails = cp.find_all_xor_linear_trails_with_weight_at_most(0, 1)
            sage: len(trails)
            13

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: key = set_fixed_variables('key', 'not_equal', list(range(16)), [0] * 16)
            sage: trails = cp.find_all_xor_linear_trails_with_weight_at_most(0, 3, fixed_values=[key])
            sage: len(trails)
            73
        """
        start = tm.time()
        self.build_xor_linear_trail_model(0, fixed_values)
        self._model_constraints.append(f'constraint weight >= {100 * min_weight} /\\ weight <= {100 * max_weight} ')
        end = tm.time()
        build_time = end - start
        if solve_with_API:
            solutions = self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, all_solutions_ = True)
        else:
            solutions = self.solve(XOR_LINEAR, solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, all_solutions_ = True, solve_external = solve_external)
            for solution in solutions:
                solution['building_time_seconds'] = build_time
                solution['test_name'] = "find_all_xor_linear_trails_with_weight_at_most"

        return solutions

    def find_lowest_weight_xor_linear_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = False):
        """
        Return the solution representing a linear trail with the lowest weight of correlation.
        By default, the search removes the key schedule, if any.

        .. NOTE::

            There could be more than one trail with the lowest weight. In order to find all the lowest weight
            trail, run :py:meth:`~find_all_xor_linear_trails_with_fixed_weight`.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: cp= MznXorLinearModel(speck)
            sage: trail = cp.find_lowest_weight_xor_linear_trail()
            sage: trail['total_weight']
            '3.0'

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: key = set_fixed_variables('key', 'not_equal', list(range(32)), [0] * 32)
            sage: trail = cp.find_lowest_weight_xor_linear_trail(fixed_values=[key])
            sage: trail['total_weight']
            '3.0'
        """
        start = tm.time()
        self.build_xor_linear_trail_model(-1, fixed_values)
        end = tm.time()
        build_time = end - start
        if solve_with_API:
            solution = self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors)
        else:
            solution = self.solve('xor_linear_one_solution', solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, solve_external = solve_external)
            solution['building_time_seconds'] = build_time
            solution['test_name'] = "find_lowest_weight_xor_linear_trail"

        return solution

    def find_one_xor_linear_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = False):
        """
        Return the solution representing a linear trail with any weight of correlation.
        By default, the search removes the key schedule, if any.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: cp.find_one_xor_linear_trail() # random

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: key = set_fixed_variables('key', 'not_equal', list(range(64)), [0] * 64)
            sage: cp.find_one_xor_linear_trail(fixed_values=[key]) # random
        """
        start = tm.time()
        self.build_xor_linear_trail_model(0, fixed_values)
        end = tm.time()
        build_time = end - start
        if solve_with_API:
            solution = self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors)
        else:
            solution = self.solve('xor_linear_one_solution', solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, solve_external = solve_external)
            solution['building_time_seconds'] = build_time
            solution['test_name'] = "find_one_xor_linear_trail"

        return solution

    def find_one_xor_linear_trail_with_fixed_weight(self, fixed_weight=-1, fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = False):
        """
        Return the solution representing a linear trail with the weight of correlation equal to ``fixed_weight``.
        By default, the search removes the key schedule, if any.

        INPUT:

        - ``fixed_weight`` -- **integer**; the value to which the weight is fixed, if non-negative
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: trail = cp.find_one_xor_linear_trail_with_fixed_weight(3)
            sage: trail['total_weight']
            '3.0'

            # including the key schedule in the model
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: key = set_fixed_variables('key', 'not_equal', list(range(16)), [0] * 16)
            sage: trail = cp.find_one_xor_linear_trail_with_fixed_weight(3, fixed_values=[key])
            sage: trail['total_weight']
            '3.0'
        """
        start = tm.time()
        self.build_xor_linear_trail_model(fixed_weight, fixed_values)
        end = tm.time()
        build_time = end - start
        if solve_with_API:
            solution = self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors)
        else:
            solution = self.solve('xor_linear_one_solution', solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, solve_external = solve_external)
            solution['building_time_seconds'] = build_time
            solution['test_name'] = "find_one_xor_linear_trail_with_fixed_weight"

        return solution

    def fix_variables_value_xor_linear_constraints(self, fixed_variables=[]):
        r"""
        Return a list of Cp constraints that fix the input variables to a specific value.

        INPUT:
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing name, bit_size,
          value (as integer) for the variables that need to be fixed to a certain value:

          {

              'component_id': 'key',

              'constraint_type': 'equal'

              'bit_positions': [0, 1, 2, 3],

              'bit_values': [1, 0, 1, 0],

          }

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: cp.fix_variables_value_xor_linear_constraints([set_fixed_variables('plaintext', 'equal', list(range(4)), integer_to_bit_list(5, 4, 'big'))])
            ['constraint plaintext_o[0] = 0 /\\ plaintext_o[1] = 1 /\\ plaintext_o[2] = 0 /\\ plaintext_o[3] = 1;']
            sage: cp.fix_variables_value_xor_linear_constraints([set_fixed_variables('plaintext', 'not_equal', list(range(4)), integer_to_bit_list(5, 4, 'big'))])
            ['constraint plaintext_o[0] != 0 \\/ plaintext_o[1] != 1 \\/ plaintext_o[2] != 0 \\/ plaintext_o[3] != 1;']
        """
        cp_constraints = []
        for component in fixed_variables:
            component_id = component['component_id']
            bit_positions = component['bit_positions']
            bit_values = component['bit_values']
            if component['constraint_type'] == 'equal':
                conditions = ' /\\ '.join(f'{component_id}_o[{value}] = {bit_values[index]}'
                                          for index, value in enumerate(bit_positions))
            elif component['constraint_type'] == 'not_equal':
                conditions = ' \\/ '.join(f'{component_id}_o[{value}] != {bit_values[index]}'
                                          for index, value in enumerate(bit_positions))
            constraint = f'constraint {conditions};'
            cp_constraints.append(constraint)

        return cp_constraints

    def get_lat_values(self, lat_table, numadd):
        lat_entries = []
        lat_values = ''
        for i in range(pow(2, numadd + 1)):
            if lat_table[i] != 0:
                binary_i = format(i, f'0{numadd + 1}b')
                lat_entries += [f'{binary_i[j]}' for j in range(numadd + 1)]
                lat_entries.append(str(round(100 * math.log2(pow(2, numadd - 1) / abs(lat_table[i])))))
            lat_values = ','.join(lat_entries)

        return lat_values

    def get_word_operation_final_xor_linear_constraints(self, component, new_constraint):
        if 'AND' in component.description[0]:
            new_constraint += f'\"{component.id}_i = \"++ ' \
                              f'show({component.id}_i)++ \"\\n\" ++ \"{component.id}_o = ' \
                              f'\"++ show({component.id}_o)++ \"\\n\" ++ show('
            for i in range(len(self.component_and_probability[component.id])):
                new_constraint += f'p[{self.component_and_probability[component.id][i]}]+'
            new_constraint = new_constraint[:-1] + ') ++ \"\\n\" ++'
        elif 'MODADD' in component.description[0]:
            new_constraint += f'\"{component.id}_i = \"++ show({component.id}_i)++ \"\\n\" ++ ' \
                              f'\"{component.id}_o = \"++ show({component.id}_o)++ \"\\n\" ++ show('
            for i in range(len(self.component_and_probability[component.id])):
                new_constraint += f'p[{self.component_and_probability[component.id][i]}]+'
            new_constraint = new_constraint[:-1] + ') ++ \"\\n\" ++'
        else:
            new_constraint += f'\"{component.id}_i = \"++ show({component.id}_i)++ \"\\n\" ' \
                              f'++\"{component.id}_o = \"++ show({component.id}_o)++ \"\\n\" ' \
                              f'++ \"0\" ++ \"\\n\" ++'

        return new_constraint

    def input_xor_linear_constraints(self):
        """
        Return lists of declarations and constraints for the first part of CP model for the xor linear model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: cp.input_xor_linear_constraints()
            (['array[0..31] of var 0..1: plaintext_o;',
              'array[0..63] of var 0..1: key_o;',
              'array[0..6] of var {0, 1600, 900, 200, 1100, 400, 1300, 600, 1500, 800, 100, 1000, 300, 1200, 500, 1400, 700}: p;',
              'var int: weight = sum(p);'],
             [])
        """
        self.sbox_mant = []
        cp_constraints = []
        and_already_added = []
        cipher_inputs = self._cipher.inputs
        cipher_inputs_bit_size = self._cipher.inputs_bit_size
        cp_declarations = [f'array[0..{cipher_inputs_bit_size[i] - 1}] of var 0..1: {element}_o;'
                           for i, element in enumerate(cipher_inputs)]
        prob_count = 0
        xor_count = 0
        valid_probabilities = {0}
        for component in self._cipher.get_all_components():
            if SBOX in component.type:
                prob_count = prob_count + 1
                self.update_sbox_lat_valid_probabilities(component, valid_probabilities)
            elif WORD_OPERATION in component.type:
                if 'AND' in component.description[0] or component.description[0] == 'OR':
                    prob_count += component.description[1] * component.output_bit_size
                    self.update_and_or_lat_valid_probabilities(and_already_added, component, cp_declarations,
                                                               valid_probabilities)
                elif 'MODADD' in component.description[0]:
                    prob_count = prob_count + component.description[1] - 1
                    output_size = component.output_bit_size
                    valid_probabilities.update({i + 100 for i in range(100 * output_size)[::100]})
                elif 'XOR' in component.description[0]:
                    if any('constant' in input_links for input_links in component.input_id_links):
                        xor_count = xor_count + 1
        cp_declarations.append(f'array[0..{prob_count - 1}] of var {valid_probabilities}: p;')
        data_type = 'int'
        cp_declarations.append(f'var {data_type}: weight = sum(p);')

        return cp_declarations, cp_constraints

    def update_and_or_lat_valid_probabilities(self, and_already_added, component, cp_declarations, valid_probabilities):
        numadd = component.description[1]
        if numadd not in and_already_added:
            lat_table = self.and_xor_linear_probability_lat(numadd)
            dim_lat = len([i for i in lat_table if i])
            set_of_occurrences = set(lat_table)
            set_of_occurrences -= {0}
            for occurrence in set_of_occurrences:
                valid_probabilities.add(round(100 * math.log2(abs(pow(2, numadd - 1) / occurrence))))
            lat_values = self.get_lat_values(lat_table, numadd)
            and_declaration = f'array [1..{dim_lat}, 1..{numadd + 2}] of int: ' \
                              f'and{numadd}inputs_LAT = array2d(1..{dim_lat}, 1..{numadd + 2}, ' \
                              f'[{lat_values}]);'
            cp_declarations.append(and_declaration)
            and_already_added.append(numadd)

    def update_sbox_lat_valid_probabilities(self, component, valid_probabilities):
        input_size = component.input_bit_size
        output_id_link = component.id
        description = component.description
        sbox = SBox(description)
        already_in = False
        for i in range(len(self.sbox_mant)):
            if description == self.sbox_mant[i][0]:
                already_in = True
        if not already_in:
            sbox_lat = sbox.linear_approximation_table()
            for i in range(sbox_lat.nrows()):
                set_of_occurrences = set(sbox_lat.rows()[i])
                set_of_occurrences -= {0}
                valid_probabilities.update(
                    {round(100 * math.log2(abs(pow(2, input_size - 1) / occurence))) for occurence in
                     set_of_occurrences})
            self.sbox_mant.append((description, output_id_link))

    def weight_xor_linear_constraints(self, weight):
        """
        Return a list of Cp constraints that fix the total weight to a specific value for xor linear model.

        INPUT:

        - ``weight`` -- **integer**; a specific weight. If set to non-negative integer, fixes the XOR trail weight

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorLinearModel(speck)
            sage: cp.weight_xor_linear_constraints(10)
            (['constraint weight = 1000;'], [])
        """
        return self.weight_constraints(weight)
