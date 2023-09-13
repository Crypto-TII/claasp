
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

from claasp.cipher_modules.models.cp.cp_model import CpModel, solve_satisfy
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, SBOX, MIX_COLUMN, WORD_OPERATION,
                                  XOR_DIFFERENTIAL, LINEAR_LAYER)


def and_xor_differential_probability_ddt(numadd):
    """
    Return the ddt of the and operation.

    INPUT:

    - ``numadd`` -- **integer**; the number of addenda

    EXAMPLES::

        sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
        ....:     and_xor_differential_probability_ddt)
        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: simon = SimonBlockCipher()
        sage: and_xor_differential_probability_ddt(2)
        [4, 0, 2, 2, 2, 2, 2, 2]
    """
    n = pow(2, numadd)
    ddt_table = []
    for i in range(n):
        for m in range(2):
            count = 0
            for j in range(n):
                k = i ^ j
                binary_j = format(j, f'0{numadd}b')
                result_j = 1
                binary_k = format(k, f'0{numadd}b')
                result_k = 1
                for index in range(numadd):
                    result_j *= int(binary_j[index])
                    result_k *= int(binary_k[index])
                difference = result_j ^ result_k
                if difference == m:
                    count += 1
            ddt_table.append(count)

    return ddt_table


def update_and_or_ddt_valid_probabilities(and_already_added, component, cp_declarations, valid_probabilities):
    numadd = component.description[1]
    if numadd not in and_already_added:
        ddt_table = and_xor_differential_probability_ddt(numadd)
        dim_ddt = len([i for i in ddt_table if i])
        ddt_entries = []
        ddt_values = ''
        set_of_occurrences = set(ddt_table)
        set_of_occurrences -= {0}
        valid_probabilities.update({round(100 * math.log2(2 ** numadd / occurrence))
                                    for occurrence in set_of_occurrences})
        for i in range(pow(2, numadd + 1)):
            if ddt_table[i] != 0:
                binary_i = format(i, f'0{numadd + 1}b')
                ddt_entries += [f'{binary_i[j]}' for j in range(numadd + 1)]
                ddt_entries.append(str(round(100 * math.log2(pow(2, numadd) / ddt_table[i]))))
            ddt_values = ','.join(ddt_entries)
        and_declaration = f'array [1..{dim_ddt}, 1..{numadd + 2}] of int: ' \
                          f'and{numadd}inputs_DDT = array2d(1..{dim_ddt}, 1..{numadd + 2}, ' \
                          f'[{ddt_values}]);'
        cp_declarations.append(and_declaration)
        and_already_added.append(numadd)


class CpXorDifferentialModel(CpModel):

    def __init__(self, cipher):
        self._first_step = []
        self._first_step_find_all_solutions = []
        self._cp_xor_differential_constraints = []
        super().__init__(cipher)

    def build_xor_differential_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the CP model for the search of XOR differential trails.

        INPUT:

        - ``weight`` -- **integer** (default: `1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight
        - ``fixed_variables`` -- **list**  (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
            ....:     CpXorDifferentialTrailSearchModel)
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64),
            ....: integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(32),
            ....: integer_to_bit_list(0, 32, 'little')))
            sage: cp.build_xor_differential_trail_model(-1, fixed_variables)
        """
        self.initialise_model()
        self.c = 0
        self.sbox_mant = []
        self.input_sbox = []
        self.component_and_probability = {}
        self.table_of_solutions_length = 0
        self.build_xor_differential_trail_model_template(weight, fixed_variables)
        variables, constraints = self.input_xor_differential_constraints()
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        self._model_constraints.extend(self.final_xor_differential_constraints(weight))
        self._model_constraints = self._model_prefix + self._variables_list + self._model_constraints

    def build_xor_differential_trail_model_template(self, weight, fixed_variables):
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
                variables, constraints = component.cp_xor_differential_propagation_constraints(self)

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self.weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def final_xor_differential_constraints(self, weight):
        """
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - ``weight`` -- **integer**; a specific weight. If set to non-negative integer, fixes the XOR trail weight

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
            ....:     CpXorDifferentialTrailSearchModel)
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64),
            ....: integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(32),
            ....: integer_to_bit_list(0, 32, 'little')))
            sage: cp.build_xor_differential_trail_model(-1, fixed_variables)
            sage: cp.final_xor_differential_constraints(-1)[:-1]
            ['solve:: int_search(p, smallest, indomain_min, complete) minimize weight;']
        """
        cipher_inputs = self._cipher.inputs
        cp_constraints = []
        if weight == -1 and self._probability:
            cp_constraints.append('solve:: int_search(p, smallest, indomain_min, complete) minimize weight;')
        else:
            cp_constraints.append(solve_satisfy)
        new_constraint = 'output['
        for element in cipher_inputs:
            new_constraint = new_constraint + f'\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for component in self._cipher.get_all_components():
            if SBOX in component.type:
                new_constraint = new_constraint + \
                    f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ ' \
                    f'show(p[{self.component_and_probability[component.id]}]/100) ++ \"\\n\" ++'
            elif WORD_OPERATION in component.type:
                new_constraint = self.get_word_operation_xor_differential_constraints(component, new_constraint)
            else:
                new_constraint = new_constraint + f'\"{component.id} = \"++ ' \
                                                  f'show({component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        new_constraint = new_constraint + '\"Trail weight = \" ++ show(weight)];'
        cp_constraints.append(new_constraint)

        return cp_constraints

    def find_all_xor_differential_trails_with_fixed_weight(self, fixed_weight, fixed_values=[], solver_name='Chuffed'):
        """
        Return a list of solutions containing all the differential trails having the ``fixed_weight`` weight.

        INPUT:

        - ``fixed_weight`` -- **integer**; the weight to be fixed
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
            ....:     CpXorDifferentialTrailSearchModel)
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: fixed_values = []
            sage: fixed_values.append(set_fixed_variables('key', 'equal', list(range(16)),
            ....: integer_to_bit_list(0, 16, 'big')))
            sage: fixed_values.append(set_fixed_variables('plaintext', 'not_equal', list(range(8)),
            ....: integer_to_bit_list(0, 8, 'big')))
            sage: trails = cp.find_all_xor_differential_trails_with_fixed_weight(1, fixed_values, 'Chuffed') # long
            ...
            sage: len(trails) # long
            6
        """
        start = tm.time()
        self.build_xor_differential_trail_model(fixed_weight, fixed_values)
        end = tm.time()
        build_time = end - start
        solutions = self.solve(XOR_DIFFERENTIAL, solver_name)
        for solution in solutions:
            solution['building_time_seconds'] = build_time

        return solutions

    def find_all_xor_differential_trails_with_weight_at_most(self, min_weight, max_weight=64, fixed_values=[],
                                                             solver_name='Chuffed'):
        """
        Return a list of solutions containing all the differential trails.

        The differential trails having the weight of correlation lying in the interval ``[min_weight, max_weight]``.

        INPUT:

        - ``min_weight`` -- **integer**; the weight from which to start the search
        - ``max_weight`` -- **integer** (default: 64); the weight at which the search stops
        - ``fixed_values`` -- **list**  (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
            ....:     CpXorDifferentialTrailSearchModel)
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=2)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: fixed_values = []
            sage: fixed_values.append(set_fixed_variables('key', 'equal', list(range(16)),
            ....: integer_to_bit_list(0, 16, 'big')))
            sage: fixed_values.append(set_fixed_variables('plaintext', 'not_equal', list(range(8)),
            ....: integer_to_bit_list(0, 8, 'big')))
            sage: trails = cp.find_all_xor_differential_trails_with_weight_at_most(0,1, fixed_values, 'Chuffed')
            ...
            sage: len(trails) # long
            7
        """
        start = tm.time()
        self.build_xor_differential_trail_model(0, fixed_values)
        self._model_constraints.append(f'constraint weight >= {100 * min_weight} /\\ weight <= {100 * max_weight} ')
        end = tm.time()
        build_time = end - start
        solutions = self.solve(XOR_DIFFERENTIAL, solver_name)
        for solution in solutions:
            solution['building_time_seconds'] = build_time

        return solutions

    def find_differential_weight(self, fixed_values=[], solver_name='Chuffed'):
        probability = 0
        self.build_xor_differential_trail_model(-1, fixed_values)
        solutions = self.solve(XOR_DIFFERENTIAL, solver_name)
        if isinstance(solutions, list):
            for solution in solutions:
                weight = solution['total_weight']
                probability += 1 / 2 ** weight
            return math.log2(1 / probability)
        else:
            return solutions['total_weight']

    def find_lowest_weight_xor_differential_trail(self, fixed_values=[], solver_name='Chuffed'):
        """
        Return the solution representing a differential trail with the lowest weight of correlation.

        .. NOTE::

            There could be more than one trail with the lowest weight. In order to find all the lowest weight
            trail, run :py:meth:`~SmtModel.find_all_xor_differential_trails_with_fixed_weight`.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
            ....:     CpXorDifferentialTrailSearchModel)
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: fixed_values = []
            sage: fixed_values.append(set_fixed_variables('key', 'equal', list(range(64)),
            ....: integer_to_bit_list(0, 64, 'big')))
            sage: fixed_values.append(set_fixed_variables('plaintext', 'not_equal', list(range(32)),
            ....: integer_to_bit_list(0, 32, 'big')))
            sage: cp.find_lowest_weight_xor_differential_trail(fixed_values,'Chuffed') # random
            {'building_time': 0.007165431976318359,
             'cipher_id': 'speck_p32_k64_o32_r4',
             'components_values': {'cipher_output_4_12': {'value': '850a9520',
             'weight': 0},
              ...
             'total_weight': '9.0'}
        """
        start = tm.time()
        self.build_xor_differential_trail_model(-1, fixed_values)
        end = tm.time()
        build_time = end - start
        solution = self.solve('xor_differential_one_solution', solver_name)
        solution['building_time_seconds'] = build_time

        return solution

    def find_one_xor_differential_trail(self, fixed_values=[], solver_name='Chuffed'):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
            ....:     CpXorDifferentialTrailSearchModel)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=[0]*32)
            sage: cp.find_one_xor_differential_trail([plaintext], 'Chuffed') # random
            {'cipher_id': 'speck_p32_k64_o32_r2',
             'model_type': 'xor_differential_one_solution',
              ...
             'cipher_output_1_12': {'value': 'ffff0000', 'weight': 0}},
             'total_weight': '18.0'}
        """
        start = tm.time()
        self.build_xor_differential_trail_model(0, fixed_values)
        end = tm.time()
        build_time = end - start
        solution = self.solve('xor_differential_one_solution', solver_name)
        solution['building_time_seconds'] = build_time

        return solution

    def find_one_xor_differential_trail_with_fixed_weight(self, fixed_weight=-1, fixed_values=[],
                                                          solver_name='Chuffed'):
        """
        Return the solution representing a differential trail with the weight of correlation equal to ``fixed_weight``.

        INPUT:

        - ``fixed_weight`` -- **integer**; the value to which the weight is fixed, if non-negative
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
            ....:     CpXorDifferentialTrailSearchModel)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=[0]*32)
            sage: cp.find_one_xor_differential_trail_with_fixed_weight(9, [plaintext], 'Chuffed') # random
            {'cipher_id': 'speck_p32_k64_o32_r5',
             'model_type': 'xor_differential_one_solution',
             ...
             'total_weight': '9.0',
             'building_time_seconds': 0.0013153553009033203}
        """
        start = tm.time()
        self.build_xor_differential_trail_model(fixed_weight, fixed_values)
        end = tm.time()
        build_time = end - start
        solution = self.solve('xor_differential_one_solution', solver_name)
        solution['building_time_seconds'] = build_time

        return solution

    def get_word_operation_xor_differential_constraints(self, component, new_constraint):
        if 'AND' in component.description[0] or 'MODADD' in component.description[0]:
            new_constraint = new_constraint + f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ show('
            for i in range(len(self.component_and_probability[component.id])):
                new_constraint = new_constraint + f'p[{self.component_and_probability[component.id][i]}]/100+'
            new_constraint = new_constraint[:-1] + ') ++ \"\\n\" ++'
        else:
            new_constraint = new_constraint + f'\"{component.id} = \"++ ' \
                                              f'show({component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'

        return new_constraint

    def input_xor_differential_constraints(self):
        """
        Return a list of CP declarations and a list of Cp constraints for the first part of the xor differential model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import (
            ....:     CpXorDifferentialTrailSearchModel)
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: cp.input_xor_differential_constraints()
            (['array[0..31] of var 0..1: plaintext;',
              'array[0..63] of var 0..1: key;',
               ...
              'array[0..31] of var 0..1: cipher_output_3_12;',
              'array[0..6] of var {0, 900, 200, 1100, 400, 1300, 600, 1500, 800, 100, 1000, 300, 1200, 500, 1400, 700}: p;',
              'var int: weight = sum(p);'],
             [])
        """
        self._cp_xor_differential_constraints = [f'array[0..{bit_size - 1}] of var 0..1: {input_};'
                           for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)]
        self.sbox_mant = []
        prob_count = 0
        valid_probabilities = {0}
        and_already_added = []
        for component in self._cipher.get_all_components():
            if CONSTANT not in component.type:
                output_id_link = component.id
                self._cp_xor_differential_constraints.append(f'array[0..{int(component.output_bit_size) - 1}] of var 0..1: {output_id_link};')
                if SBOX in component.type:
                    prob_count += 1
                    self.update_sbox_ddt_valid_probabilities(component, valid_probabilities)
                elif WORD_OPERATION in component.type:
                    if 'AND' in component.description[0] or component.description[0] == 'OR':
                        prob_count += component.description[1] * component.output_bit_size
                        update_and_or_ddt_valid_probabilities(and_already_added, component, self._cp_xor_differential_constraints,
                                                              valid_probabilities)
                    elif 'MODADD' in component.description[0]:
                        prob_count += component.description[1] - 1
                        output_size = component.output_bit_size
                        valid_probabilities |= set(range(100 * output_size)[::100])
        cp_declarations_weight = 'int: weight = 0;'
        if prob_count > 0:
            self._probability = True
            new_declaration = f'array[0..{prob_count - 1}] of var {valid_probabilities}: p;'
            self._cp_xor_differential_constraints.append(new_declaration)
            cp_declarations_weight = 'var int: weight = sum(p);'
        self._cp_xor_differential_constraints.append(cp_declarations_weight)
        cp_constraints = []

        return self._cp_xor_differential_constraints, cp_constraints

    def update_sbox_ddt_valid_probabilities(self, component, valid_probabilities):
        input_size = int(component.input_bit_size)
        output_id_link = component.id
        description = component.description
        sbox = SBox(description)
        sbox_already_in = False
        for mant in self.sbox_mant:
            if description == mant[0]:
                sbox_already_in = True
        if not sbox_already_in:
            sbox_ddt = sbox.difference_distribution_table()
            for i in range(sbox_ddt.nrows()):
                set_of_occurrences = set(sbox_ddt.rows()[i])
                set_of_occurrences -= {0}
                valid_probabilities.update({round(100 * math.log2(2 ** input_size / occurrence))
                                            for occurrence in set_of_occurrences})
            self.sbox_mant.append((description, output_id_link))
