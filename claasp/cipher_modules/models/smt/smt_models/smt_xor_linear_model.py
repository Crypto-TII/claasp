
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

from claasp.cipher_modules.models.smt.utils import constants, utils
from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.cipher_modules.models.utils import get_bit_bindings
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER,
                                  MIX_COLUMN, SBOX, WORD_OPERATION, XOR_LINEAR)


class SmtXorLinearModel(SmtModel):
    def __init__(self, cipher, counter='sequential'):
        super().__init__(cipher, counter)
        self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(cipher, '_'.join)

    def branch_xor_linear_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts for branch in XOR LINEAR model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorLinearModel(speck)
            sage: smt.branch_xor_linear_constraints()
            ['(assert (not (xor plaintext_0_o rot_0_0_0_i)))',
             '(assert (not (xor plaintext_1_o rot_0_0_1_i)))',
             ...
             '(assert (not (xor xor_2_10_14_o cipher_output_2_12_30_i)))',
             '(assert (not (xor xor_2_10_15_o cipher_output_2_12_31_i)))']
        """
        return [utils.smt_assert(utils.smt_not(utils.smt_xor([output_bit] + input_bits)))
                for output_bit, input_bits in self.bit_bindings.items()]

    def build_xor_linear_trail_model(self, weight=-1, fixed_variables=[]):
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
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: smt = SmtXorLinearModel(speck)
            sage: smt.build_xor_linear_trail_model()
        """
        self._variables_list = []
        variables = []
        constraints = self.fix_variables_value_xor_linear_constraints(fixed_variables)
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            component_types = (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                               SBOX, MIX_COLUMN, WORD_OPERATION)
            operation = component.description[0]
            operation_types = ("AND", "MODADD", "NOT", "ROTATE", "SHIFT", "XOR", "OR", "MODSUB")
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.smt_xor_linear_mask_propagation_constraints(self)
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

        self._variables_list.extend(self.cipher_input_xor_linear_variables())
        self._declarations_builder()
        self._model_constraints = \
            constants.MODEL_PREFIX + self._declarations + self._model_constraints + constants.MODEL_SUFFIX

    def cipher_input_xor_linear_variables(self):
        """
        Return the list of input variables.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorLinearModel(speck)
            sage: smt.cipher_input_xor_linear_variables()
            ['plaintext_0_o',
             'plaintext_1_o',
             ...
             'key_62_o',
             'key_63_o']
        """
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        cipher_input_bit_ids = [f'{input_id}_{j}{out_suffix}'
                                for input_id, size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
                                for j in range(size)]

        return cipher_input_bit_ids

    def find_all_xor_linear_trails_with_fixed_weight(self, fixed_weight, fixed_values=[], solver_name='z3'):
        """
        Return a list of solutions containing all the XOR linear trails having weight equal to ``fixed_weight``.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `z3`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorLinearModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=integer_to_bit_list(0, 32, 'big'))
            sage: trails = smt.find_all_xor_linear_trails_with_fixed_weight(2, fixed_values=[plaintext])
            sage: len(trails) == 2
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
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        while solution['total_weight'] is not None:
            solutions_list.append(solution)
            operands = []
            for component in self._cipher.get_all_components():
                bit_len = component.output_bit_size
                if component.type == SBOX or \
                        (component.type == WORD_OPERATION and
                         component.description[0] in ('AND', 'MODADD', 'MODSUB', 'OR', 'SHIFT_BY_VARIABLE_AMOUNT')):
                    value_to_avoid = int(solution['components_values'][f'{component.id}{out_suffix}']['value'], base=16)
                    operands.extend([utils.smt_not(f'{component.id}_{j}{out_suffix}')
                                     if value_to_avoid >> (bit_len - 1 - j) & 1
                                     else f'{component.id}_{j}{out_suffix}'
                                     for j in range(bit_len)])
            clause = utils.smt_or(operands)
            self._model_constraints = self._model_constraints[:-len(constants.MODEL_SUFFIX)] \
                                      + [utils.smt_assert(clause)] + constants.MODEL_SUFFIX
            solution = self.solve(XOR_LINEAR, solver_name=solver_name)
            solution['building_time_seconds'] = end_building_time - start_building_time

        return solutions_list

    def find_all_xor_linear_trails_with_weight_at_most(self, min_weight, max_weight, fixed_values=[], solver_name='z3'):
        """
        Return a list of solutions.

        The list contains all the XOR linear trails having the weight lying in the interval
        ``[min_weight, max_weight]``.

        INPUT:

        - ``min_weight`` -- **integer**; the weight from which to start the search
        - ``max_weight`` -- **integer**; the weight at which the search stops
        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `z3`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorLinearModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=integer_to_bit_list(0, 32, 'big'))
            sage: trails = smt.find_all_xor_linear_trails_with_weight_at_most(2, 3, fixed_values=[plaintext])
            sage: len(trails) == 11
            True
        """
        solutions_list = []
        for weight in range(min_weight, max_weight + 1):
            solutions = self.find_all_xor_linear_trails_with_fixed_weight(weight,
                                                                          fixed_values=fixed_values,
                                                                          solver_name=solver_name)
            solutions_list.extend(solutions)

        return solutions_list

    def find_lowest_weight_xor_linear_trail(self, fixed_values=[], solver_name='z3'):
        """
        Return the solution representing a XOR LINEAR trail with the lowest possible weight.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        .. NOTE::

            There could be more than one trail with the lowest weight. In order to find all the lowest weight trail,
            run :py:meth:`~find_all_xor_linear_trails_with_fixed_weight`

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `z3`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorLinearModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=integer_to_bit_list(0, 32, 'big'))
            sage: trail = smt.find_lowest_weight_xor_linear_trail(fixed_values=[plaintext])
            sage: trail['total_weight']
            2.0
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

        return solution

    def find_one_xor_linear_trail(self, fixed_values=[], solver_name='z3'):
        """
        Return the solution representing a XOR linear trail.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        The solution probability is almost always lower than the one of a random guess of the longest input.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); they can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `z3`); the name of the solver

        .. SEEALSO::

            :ref:`smt-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: smt = SmtXorLinearModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=integer_to_bit_list(0, 32, 'big'))
            sage: smt.find_one_xor_linear_trail(fixed_values=[plaintext]) #random
            {'cipher_id': 'speck_p32_k64_o32_r4',
             'model_type': 'xor_linear',
             'solver_name': 'z3',
             'solving_time_seconds': 0.06,
             'memory_megabytes': 19.65,
             ...
             'total_weight': 67,
             'building_time_seconds': 0.003168344497680664}
        """
        start_building_time = time.time()
        self.build_xor_linear_trail_model(fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(XOR_LINEAR, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time

        return solution

    def find_one_xor_linear_trail_with_fixed_weight(self, fixed_weight, fixed_values=[],
                                                    solver_name='z3'):
        """
        Return the solution representing a XOR linear trail whose weight is ``fixed_weight``.
        By default, the weight corresponds to the negative base-2 logarithm of the correlation of the trail.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `cryptominisat`); the name of the solver

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorLinearModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=(0,)*32)
            sage: result = smt.find_one_xor_linear_trail_with_fixed_weight(7, fixed_values=[plaintext])
            sage: result['total_weight']
            7.0
        """
        start_building_time = time.time()
        self.build_xor_linear_trail_model(weight=fixed_weight, fixed_variables=fixed_values)
        if self._counter == self._sequential_counter:
            self._sequential_counter_greater_or_equal(fixed_weight, 'dummy_hw_1')
        end_building_time = time.time()
        solution = self.solve(XOR_LINEAR, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time

        return solution

    def fix_variables_value_xor_linear_constraints(self, fixed_variables=[]):
        """
        Return a variable list and SMT-LIB list asserts for fixing variables in XOR LINEAR model.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); variables in default format

        EXAMPLES::

            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: smt = SmtXorLinearModel(speck)
            sage: smt.fix_variables_value_xor_linear_constraints([set_fixed_variables('plaintext', 'equal', range(4), integer_to_bit_list(5, 4, 'big'))])
            ['(assert (not plaintext_0_o))',
             '(assert plaintext_1_o)',
             '(assert (not plaintext_2_o))',
             '(assert plaintext_3_o)']
            sage: smt.fix_variables_value_xor_linear_constraints([set_fixed_variables('plaintext', 'not_equal', range(4), integer_to_bit_list(5, 4, 'big'))])
            ['(assert (or plaintext_0_o (not plaintext_1_o) plaintext_2_o (not plaintext_3_o)))']
        """
        constraints = []
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        for component in fixed_variables:
            component_id = component['component_id']
            bit_positions = component['bit_positions']
            bit_values = component['bit_values']

            if component['constraint_type'] not in ('equal', 'not_equal'):
                raise ValueError('constraint type not defined or misspelled.')

            if component['constraint_type'] == 'equal':
                self.update_constraints_for_equal_type(bit_positions, bit_values, component_id, constraints, out_suffix)
            else:
                self.update_constraints_for_not_equal_type(bit_positions, bit_values,
                                                           component_id, constraints, out_suffix)

        return constraints

    def weight_xor_linear_constraints(self, weight):
        return self.weight_constraints(weight)
