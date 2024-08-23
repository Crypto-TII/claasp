
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
import math
import itertools
import subprocess

from claasp.cipher_modules.models.cp.cp_model import CpModel, solve_satisfy
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary, check_if_implemented_component
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL)
from claasp.cipher_modules.models.cp.solvers import MODEL_DEFAULT_PATH, SOLVER_DEFAULT


class CpDeterministicTruncatedXorDifferentialModel(CpModel):

    def __init__(self, cipher):
        super().__init__(cipher)

    def add_solutions_from_components_values(self, components_values, memory, model_type, solutions, solve_time,
                                             solver_name, solver_output):
        for nsol in components_values.keys():
            solution = convert_solver_solution_to_dictionary(
                self.cipher_id,
                model_type,
                solver_name,
                solve_time,
                memory,
                components_values[nsol],
                0)
            if 'UNSATISFIABLE' in solver_output[0]:
                solution['status'] = 'UNSATISFIABLE'
            else:
                solution['status'] = 'SATISFIABLE'
            solutions.append(solution)

    def add_solution_to_components_values(self, component_id, component_solution, components_values, j, output_to_parse,
                                          solution_number, string):
        if component_id in self._cipher.inputs:
            components_values[f'solution{solution_number}'][f'{component_id}'] = component_solution
        elif f'{component_id}_i' in string:
            components_values[f'solution{solution_number}'][f'{component_id}_i'] = component_solution
        elif f'{component_id}_o' in string:
            components_values[f'solution{solution_number}'][f'{component_id}_o'] = component_solution
        elif f'{component_id} ' in string:
            components_values[f'solution{solution_number}'][f'{component_id}'] = component_solution
    
    def build_deterministic_truncated_xor_differential_trail_model(self, fixed_variables=[], number_of_rounds=None, minimize=False, wordwise=False):
        """
        Build the CP model for the search of deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: cp.build_deterministic_truncated_xor_differential_trail_model(fixed_variables)
        """
        self.initialise_model()
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        deterministic_truncated_xor_differential = constraints

        for component in self._cipher.get_all_components():
            if check_if_implemented_component(component):
                variables, constraints = self.propagate_deterministically(component, wordwise)
                self._variables_list.extend(variables)
                deterministic_truncated_xor_differential.extend(constraints)
        
        if not wordwise:
            variables, constraints = self.input_deterministic_truncated_xor_differential_constraints()
        else:
            variables, constraints = self.input_wordwise_deterministic_truncated_xor_differential_constraints()
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        if not wordwise:
            deterministic_truncated_xor_differential.extend(self.final_deterministic_truncated_xor_differential_constraints(minimize))
        else:
            deterministic_truncated_xor_differential.extend(self.final_wordwise_deterministic_truncated_xor_differential_constraints(minimize))
        self._model_constraints = self._model_prefix + self._variables_list + deterministic_truncated_xor_differential

    def final_deterministic_truncated_xor_differential_constraints(self, minimize=False):
        """
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: cp.final_deterministic_truncated_xor_differential_constraints()[:-1]
            ['solve satisfy;']
        """
        cipher_inputs = self._cipher.inputs
        cipher = self._cipher
        cp_constraints = []
        new_constraint = 'output['
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for component_id in cipher.get_all_components_ids():
            new_constraint = new_constraint + \
                f'\"{component_id} = \"++ show({component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
            if 'cipher_output' in component_id and minimize:
                cp_constraints.append(f'solve maximize count({self._cipher.get_all_components_ids()[-1]}, 0);')
        new_constraint = new_constraint[:-2] + '];'
        if cp_constraints == []:
            cp_constraints.append(solve_satisfy)
        cp_constraints.append(new_constraint)

        return cp_constraints

    def find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(self, number_of_rounds=None,
                                                                fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=[0]*32)
            sage: key = set_fixed_variables(
            ....:         component_id='key',
            ....:         constraint_type='equal',
            ....:         bit_positions=range(64),
            ....:         bit_values=[0]*64)
            sage: cp.find_one_deterministic_truncated_xor_differential_trail(1, [plaintext,key], 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r1',
              'components_values': {'cipher_output_0_6': {'value': '22222222222222212222222222222220',
                'weight': 0},
               'intermediate_output_0_5': {'value': '0000000000000000', 'weight': 0},
               'key': {'value': '0000000000000000000000000000000000000000000000000000000000000000',
                'weight': 0},
               'modadd_0_1': {'value': '2222222222222221', 'weight': 0},
               'plaintext': {'value': '11111111011111111111111111111111', 'weight': 0},
               'rot_0_0': {'value': '1111111111111110', 'weight': 0},
               'rot_0_3': {'value': '1111111111111111', 'weight': 0},
               'xor_0_2': {'value': '2222222222222221', 'weight': 0},
               'xor_0_4': {'value': '2222222222222220', 'weight': 0}},
              'memory_megabytes': 0.01,
              'model_type': 'deterministic_truncated_xor_differential_one_solution',
              'solver_name': 'Chuffed',
              'solving_time_seconds': 0.0,
              'total_weight': '0.0'}]
        """
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        self.build_deterministic_truncated_xor_differential_trail_model(fixed_values, number_of_rounds, minimize = True)

        return self.solve('deterministic_truncated_xor_differential_one_solution', solver_name, num_of_processors, timelimit)

    def find_all_deterministic_truncated_xor_differential_trail(self, number_of_rounds=None,
                                                                fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``number_of_rounds`` -- **integer**; number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `None`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=[0]*32)
            sage: key = set_fixed_variables(
            ....:         component_id='key',
            ....:         constraint_type='equal',
            ....:         bit_positions=range(64),
            ....:         bit_values=[0]*64)
            sage: cp.find_all_deterministic_truncated_xor_differential_trail(3, [plaintext,key], 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r3',
              'components_values': {'cipher_output_2_12': {'value': '22222222222222202222222222222222',
                'weight': 0},
              ...
              'memory_megabytes': 0.02,
              'model_type': 'deterministic_truncated_xor_differential',
              'solver_name': 'Chuffed',
              'solving_time_seconds': 0.002,
              'total_weight': '0.0'}]
        """
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        self.build_deterministic_truncated_xor_differential_trail_model(fixed_values, number_of_rounds)

        return self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name, num_of_processors, timelimit)

    def find_one_deterministic_truncated_xor_differential_trail(self, number_of_rounds=None,
                                                                fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=[0]*32)
            sage: key = set_fixed_variables(
            ....:         component_id='key',
            ....:         constraint_type='equal',
            ....:         bit_positions=range(64),
            ....:         bit_values=[0]*64)
            sage: cp.find_one_deterministic_truncated_xor_differential_trail(1, [plaintext,key], 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r1',
              'components_values': {'cipher_output_0_6': {'value': '22222222222222212222222222222220',
                'weight': 0},
               'intermediate_output_0_5': {'value': '0000000000000000', 'weight': 0},
               'key': {'value': '0000000000000000000000000000000000000000000000000000000000000000',
                'weight': 0},
               'modadd_0_1': {'value': '2222222222222221', 'weight': 0},
               'plaintext': {'value': '11111111011111111111111111111111', 'weight': 0},
               'rot_0_0': {'value': '1111111111111110', 'weight': 0},
               'rot_0_3': {'value': '1111111111111111', 'weight': 0},
               'xor_0_2': {'value': '2222222222222221', 'weight': 0},
               'xor_0_4': {'value': '2222222222222220', 'weight': 0}},
              'memory_megabytes': 0.01,
              'model_type': 'deterministic_truncated_xor_differential_one_solution',
              'solver_name': 'Chuffed',
              'solving_time_seconds': 0.0,
              'total_weight': '0.0'}]
        """
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        self.build_deterministic_truncated_xor_differential_trail_model(fixed_values, number_of_rounds)

        return self.solve('deterministic_truncated_xor_differential_one_solution', solver_name, num_of_processors, timelimit)

    def input_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of CP constraints for the inputs of the cipher for the first step model.

        INPUT:

        - ``number_of_rounds`` -- **integer**; number of rounds
        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: aes = AESBlockCipher()
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(aes)
            sage: cp.input_deterministic_truncated_xor_differential_constraints()
            (['array[0..127] of var 0..2: key;',
              'array[0..127] of var 0..2: plaintext;',
               ...
              'constraint count(plaintext,1) > 0;'])
        """
        number_of_rounds = self._cipher.number_of_rounds

        cp_constraints = []
        cp_declarations = [f'array[0..{bit_size - 1}] of var 0..2: {input_};'
                           for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)]
        cipher = self._cipher
        rounds = number_of_rounds
        for component in cipher.get_all_components():
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
                cp_constraints.append(f'constraint count({output_id_link},2) < {output_size};')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
        cp_constraints.append('constraint count(plaintext,1) > 0;')

        return cp_declarations, cp_constraints

    def output_constraints(self, component):
        """
        Return lists of declarations and constraints for CP output component (both intermediate and cipher).

        INPUT:

        - ``component`` -- **Component object**; the output component (intermediate or cipher) in Cipher

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: output_component = speck.component_from(0, 5)
            sage: cp.output_constraints(output_component)
            ([],
             ['constraint intermediate_output_0_5[0] = key[48];',
             ...
              'constraint intermediate_output_0_5[15] = key[63];'])
        """
        output_size = int(component.output_bit_size)
        input_id_links = component.input_id_links
        output_id_link = component.id
        input_bit_positions = component.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = [f'constraint {output_id_link}[{i}] = {all_inputs[i]};' for i in range(output_size)]

        return cp_declarations, cp_constraints

    def output_inverse_constraints(self, component):
        """
        Return lists of declarations and constraints for CP output component (both intermediate and cipher).

        INPUT:

        - ``component`` -- **Component object**; the output component (intermediate or cipher)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: output_component = speck.component_from(0, 5)
            sage: cp.output_inverse_constraints(output_component)
            ([],
             ['constraint intermediate_output_0_5_inverse[0] = key[48];',
               ...
              'constraint intermediate_output_0_5_inverse[15] = key[63];'])
        """
        output_size = int(component.output_bit_size)
        input_id_links = component.input_id_links
        output_id_link = component.id
        input_bit_positions = component.input_bit_positions
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
            all_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
        cp_constraints = [f'constraint {output_id_link}_inverse[{i}] = {all_inputs[i]};'
                          for i in range(output_size)]

        return cp_declarations, cp_constraints
        
    def format_component_value(self, component_id, string):
        if f'{component_id}_i' in string:
            value = string.replace(f'{component_id}_i', '')
        elif f'{component_id}_o' in string:
            value = string.replace(f'{component_id}_o', '')
        elif f'inverse_{component_id}' in string:
            value = string.replace(f'inverse_{component_id}', '')
        elif f'{component_id}' in string:
            value = string.replace(component_id, '')
        value = value.replace('= [', '')
        value = value.replace(']', '')
        value = value.replace(',', '')
        value = value.replace(' ', '')

        return value

    def parse_solver_information(self, output_to_parse):
        memory = -1
        time = -1
        string_total_weight = []
        components_values = {}
        number_of_solutions = 1
        for string in output_to_parse:
            if 'time=' in string:
                time_string = string
                time = float(time_string.replace("%%%mzn-stat: time=", ""))
            elif 'solveTime=' in string:
                time_string = string
                time = float(time_string.replace("%%%mzn-stat: solveTime=", ""))
            elif 'trailMem=' in string:
                memory_string = string
                memory = float(memory_string.replace("%%%mzn-stat: trailMem=", ""))
            elif '----------' in string:
                string_total_weight.append("0")
                components_values[f'solution{number_of_solutions}'] = {}
                number_of_solutions += 1
        if number_of_solutions == 1:
            components_values = {}

        return components_values, memory, time

    def _parse_solver_output(self, output_to_parse, model_type):
        """
        Parse solver solution (if needed).

        INPUT:

        - ``output_to_parse`` -- **list**; strings that represents the solver output
        - ``truncated`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_model import CpXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, write_model_to_file
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: cp.build_xor_differential_trail_model(-1, fixed_variables)
            sage: write_model_to_file(cp._model_constraints,'doctesting_file.mzn')
            sage: command = ['minizinc', '--solver-statistics', '--solver', 'Chuffed', 'doctesting_file.mzn']
            sage: import subprocess
            sage: solver_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
            sage: os.remove('doctesting_file.mzn')
            sage: solver_output = solver_process.stdout.splitlines()
            sage: cp._parse_solver_output(solver_output) # random
            (0.018,
             ...
             'cipher_output_3_12': {'value': '0', 'weight': 0}}},
             ['0'])
        """
        components_values, memory, time = self.parse_solver_information(output_to_parse)
        all_components = [*self._cipher.inputs, *self._cipher.get_all_components_ids()]
        for component_id in all_components:
            solution_number = 1
            for j, string in enumerate(output_to_parse):
                if f'{component_id}' in string or f'{component_id}_i' in string or f'{component_id}_o' in string or f'inverse_{component_id}' in string:
                    value = self.format_component_value(component_id, string)
                    component_solution = {}
                    component_solution['value'] = value
                    self.add_solution_to_components_values(component_id, component_solution, components_values, j,
                                                           output_to_parse, solution_number, string)
                elif '----------' in string:
                    solution_number += 1
        if 'impossible' in model_type and solution_number > 1:
            for nsol in components_values.keys():
                components_values[nsol] = self.extract_incompatibilities_from_output(components_values[nsol])

        return time, memory, components_values
        
    def propagate_deterministically(self, component, wordwise=False):
        if not wordwise:
            if component.type == SBOX:
                variables, constraints, sbox_mant = component.cp_deterministic_truncated_xor_differential_trail_constraints(self.sbox_mant)
                self.sbox_mant = sbox_mant
            else:
                variables, constraints = component.cp_deterministic_truncated_xor_differential_trail_constraints()
        else:
            variables, constraints = component.cp_wordwise_deterministic_truncated_xor_differential_constraints(self)
            
        return variables, constraints
            
    def solve(self, model_type, solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None):
        """
        Return the solution of the model.

        INPUT:

        - ``model_type`` -- **string**; the model to solve:

          * 'cipher'
          * 'xor_differential'
          * 'xor_differential_one_solution'
          * 'xor_linear'
          * 'xor_linear_one_solution'
          * 'deterministic_truncated_xor_differential'
          * 'deterministic_truncated_xor_differential_one_solution'
          * 'impossible_xor_differential'
        - ``solver_name`` -- **string** (default: `None`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        - ``num_of_processors`` -- **integer**; the number of processors to be used
        - ``timelimit`` -- **integer**; time limit to output a result

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_model import CpXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', list(range(64)), integer_to_bit_list(0, 64, 'little')), set_fixed_variables('plaintext', 'not_equal', list(range(32)), integer_to_bit_list(0, 32, 'little'))]
            sage: cp.build_xor_differential_trail_model(-1, fixed_variables)
            sage: cp.solve('xor_differential', 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r4',
              ...
              'total_weight': '7'},
             {'cipher_id': 'speck_p32_k64_o32_r4',
               ...
              'total_weight': '5'}]
        """
        
        cipher_name = self.cipher_id
        input_file_path = f'{MODEL_DEFAULT_PATH}/{cipher_name}_Cp_{model_type}_{solver_name}.mzn'
        command = self.get_command_for_solver_process(
            input_file_path, model_type, solver_name, num_of_processors, timelimit
        )
        solver_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        os.remove(input_file_path)
        if solver_process.returncode >= 0:
            solutions = []
            solver_output = solver_process.stdout.splitlines()
            if model_type in ['deterministic_truncated_xor_differential',
                              'deterministic_truncated_xor_differential_one_solution',
                              'impossible_xor_differential',
                              'impossible_xor_differential_one_solution']:
                solve_time, memory, components_values = self._parse_solver_output(solver_output, model_type)
                total_weight = 0
            else:
                solve_time, memory, components_values, total_weight = self._parse_solver_output(solver_output, model_type)
            if components_values == {}:
                solution = convert_solver_solution_to_dictionary(self.cipher_id, model_type, solver_name,
                                                                 solve_time, memory,
                                                                 components_values, total_weight)
                if 'UNSATISFIABLE' in solver_output[0]:
                    solution['status'] = 'UNSATISFIABLE'
                else:
                    solution['status'] = 'SATISFIABLE'
                solutions.append(solution)
            else:
                self.add_solutions_from_components_values(components_values, memory, model_type, solutions, solve_time,
                                                          solver_name, solver_output)
            if model_type in ['xor_differential_one_solution',
                              'xor_linear_one_solution',
                              'deterministic_truncated_one_solution',
                              'impossible_xor_differential_one_solution']:
                return solutions[0]
            else:
                return solutions

