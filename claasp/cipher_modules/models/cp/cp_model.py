
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

from sage.crypto.sbox import SBox

from claasp.cipher_modules.component_analysis_tests import branch_number
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary
from claasp.name_mappings import SBOX

solve_satisfy = 'solve satisfy;'
constraint_type_error = 'Constraint type not defined'


class CpModel:

    def __init__(self, cipher):
        self._cipher = cipher
        self.initialise_model()
        
    def initialise_model(self):
        self._variables_list = []
        self._model_constraints = []
        self.c = 0
        if self._cipher.is_spn():
            for component in self._cipher.get_all_components():
                if SBOX in component.type:
                    self.word_size = int(component.output_bit_size)
                    break
        self._float_and_lat_values = []
        self._probability = False
        self.sbox_mant = []
        self.mix_column_mant = []
        self.modadd_twoterms_mant = []
        self.input_sbox = []
        self.table_of_solutions_length = 0
        self.list_of_xor_components = []
        self.list_of_xor_all_inputs = []
        self.component_and_probability = {}
        self._model_prefix = [
            'include "globals.mzn";',
            'include "claasp/cipher_modules/models/cp/Minizinc_functions/Usefulfunctions.mzn";']

    def add_solutions_from_components_values(self, components_values, memory, model_type, solutions, solve_time,
                                             solver_name, solver_output, total_weight):
        for i in range(len(total_weight)):
            solution = convert_solver_solution_to_dictionary(
                self.cipher_id,
                model_type,
                solver_name,
                solve_time,
                memory,
                components_values[f'solution{i + 1}'],
                total_weight[i])
            if 'UNSATISFIABLE' in solver_output[0]:
                solution['status'] = 'UNSATISFIABLE'
            else:
                solution['status'] = 'SATISFIABLE'
            solutions.append(solution)

    def add_solution_to_components_values(self, component_id, component_solution, components_values, j, output_to_parse,
                                          solution_number, string):
        if component_id in self._cipher.inputs:
            component_solution['weight'] = 0
            components_values[f'solution{solution_number}'][f'{component_id}'] = component_solution
        elif f'{component_id}_i' in string:
            component_solution['weight'] = float(output_to_parse[j + 2])
            components_values[f'solution{solution_number}'][f'{component_id}_i'] = component_solution
        elif f'{component_id}_o' in string:
            component_solution['weight'] = float(output_to_parse[j + 1])
            components_values[f'solution{solution_number}'][f'{component_id}_o'] = component_solution
        elif f'{component_id} ' in string:
            component_solution['weight'] = float(output_to_parse[j + 1])
            components_values[f'solution{solution_number}'][f'{component_id}'] = component_solution

    def build_mix_column_truncated_table(self, component):
        """
        Return a model that generates the list of possible input/output  couples for the given mix column.

        INPUT:

        - ``component`` -- **Component object**; the mix column component in Cipher

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: mix_column = aes.component_from(0, 21)
            sage: cp.build_mix_column_truncated_table(mix_column)
            'array[0..93, 1..8] of int: mix_column_truncated_table_mix_column_0_21 = array2d(0..93, 1..8, [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,0,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,1,0,1,0,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,0,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1]);'
        """
        input_size = int(component.input_bit_size)
        output_size = int(component.output_bit_size)
        output_id_link = component.id
        branch = branch_number(component, 'differential', 'word')
        total_size = (input_size + output_size) // self.word_size
        table_items = ''
        solutions = 0
        for i in range(2 ** total_size):
            binary_i = f'{i:0{total_size}b}'
            bit_sum = sum(int(x) for x in binary_i)
            if bit_sum == 0 or bit_sum >= branch:
                table_items += binary_i
                solutions += 1
        table = ','.join(table_items)
        mix_column_table = f'array[0..{solutions - 1}, 1..{total_size}] of int: ' \
                           f'mix_column_truncated_table_{output_id_link} = ' \
                           f'array2d(0..{solutions - 1}, 1..{total_size}, [{table}]);'

        return mix_column_table

    def calculate_bit_positions(self, bit_positions, input_length):
        new_bit_positions = []
        for i in range(input_length):
            new_value = bit_positions[i * self.word_size] // self.word_size
            new_bit_positions.append(new_value)

        return new_bit_positions

    def calculate_bit_values(self, bit_values, input_length):
        new_bit_values = []
        for i in range(input_length):
            partial_sum = 0
            for j in range(self.word_size):
                partial_sum = partial_sum + bit_values[i * self.word_size + j]
            if partial_sum > 0:
                new_bit_values.append(1)
            else:
                new_bit_values.append(0)

        return new_bit_values

    def calculate_input_bit_positions(self, word_index, input_name_1, input_name_2, new_input_bit_positions_1,
                                      new_input_bit_positions_2):
        input_bit_positions = [[] for _ in range(3)]
        if input_name_1 != input_name_2:
            input_bit_positions[0] = [int(new_input_bit_positions_1) * self.word_size + index
                                      for index in range(self.word_size)]
            input_bit_positions[1] = [word_index * self.word_size + index for index in range(self.word_size)]
            input_bit_positions[2] = [int(new_input_bit_positions_2) * self.word_size + index
                                      for index in range(self.word_size)]
        else:
            input_bit_positions[0] = [int(new_input_bit_positions_1) * self.word_size + index
                                      for index in range(self.word_size)]
            input_bit_positions[0] += [int(new_input_bit_positions_2) * self.word_size + index
                                       for index in range(self.word_size)]
            input_bit_positions[1] = [word_index * self.word_size + index for index in range(self.word_size)]

        return input_bit_positions

    def find_possible_number_of_active_sboxes(self, weight):
        """
        Return a set whose numbers are the possible numbers of active S-boxes.

        INPUT:

        - ``weight`` -- **integer**; the fixed weight that must be able to be obtained with the found numbers of active S-boxes

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: midori = MidoriBlockCipher()
            sage: cp = CpModel(midori)
            sage: model = cp.find_possible_number_of_active_sboxes(9)
            sage: model
            {3, 4}
        """
        set_of_sboxes_values = set()
        for component in self._cipher.get_all_components():
            if SBOX in component.type:
                set_of_sboxes_values.add(tuple(component.description))
                input_size = component.input_bit_size
        allowed_hw = set()
        for sbox_values in set_of_sboxes_values:
            sbox_ddt = SBox(sbox_values).difference_distribution_table()
            for i in range(sbox_ddt.nrows()):
                set_of_occurences = set(sbox_ddt.rows()[i])
                set_of_occurences -= {0}
                for occurence in set_of_occurences:
                    allowed_hw.add(round(100 * math.log2(2**input_size / occurence)) / 100)
        allowed_hw -= {0}
        min_number_of_sboxes = int(weight / max(allowed_hw))
        max_number_of_sboxes = math.ceil(weight / min(allowed_hw))
        numbers_of_active_sboxes = set()
        for i in range(min_number_of_sboxes, max_number_of_sboxes + 1):
            partitions = itertools.combinations_with_replacement(allowed_hw, i)
            for partition in partitions:
                total = sum(partition)
                if total == weight:
                    numbers_of_active_sboxes.add(len(partition))

        return numbers_of_active_sboxes

    def fix_variables_value_constraints(self, fixed_variables=[], step='full_model'):
        r"""
        Return a list of CP constraints that fix the input variables to a specific value.

        INPUT:

        - ``fixed_variables`` -- **list**  (default: `[]`); dictionaries containing name, bit_size,
          value (as integer) for the variables that need to be fixed to a certain value:

          {
              'component_id': 'plaintext',

              'constraint_type': 'equal'/'not_equal'

              'bit_size': 32,

              'value': 753

          }
        - ``step`` -- **string** (default: `full_model`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpModel(speck)
            sage: cp.fix_variables_value_constraints([set_fixed_variables('plaintext', 'equal', range(4), integer_to_bit_list(5, 4, 'big'))])
            ['constraint plaintext[0] = 0 /\\ plaintext[1] = 1 /\\ plaintext[2] = 0 /\\ plaintext[3] = 1;']
            sage: cp.fix_variables_value_constraints([set_fixed_variables('plaintext', 'not_equal', list(range(4)), integer_to_bit_list(5, 4, 'big'))])
            ['constraint plaintext[0] != 0 \\/ plaintext[1] != 1 \\/ plaintext[2] != 0 \\/ plaintext[3] != 1;']
        """
        cp_constraints = []
        for component in fixed_variables:
            component_id = component['component_id']
            bit_positions = component['bit_positions']
            bit_values = component['bit_values']
            if step == 'first_step':
                if not self._cipher.is_spn():
                    raise ValueError('Cipher is not SPN')
                input_length = len(bit_positions) // self.word_size
                bit_positions = self.calculate_bit_positions(bit_positions, input_length)
                bit_values = self.calculate_bit_values(bit_values, input_length)
            if component['constraint_type'] == 'equal':
                sign = '='
                logic_operator = ' /\\ '
            elif component['constraint_type'] == 'not_equal':
                sign = '!='
                logic_operator = ' \\/ '
            else:
                raise ValueError(constraint_type_error)
            values_constraints = [f'{component_id}[{position}] {sign} {bit_values[i]}'
                                  for i, position in enumerate(bit_positions)]
            new_constraint = 'constraint ' + f'{logic_operator}'.join(values_constraints) + ';'
            cp_constraints.append(new_constraint)

        return cp_constraints

    def format_component_value(self, component_id, string):
        if f'{component_id}_i' in string:
            value = string.replace(f'{component_id}_i', '')
        elif f'{component_id}_o' in string:
            value = string.replace(f'{component_id}_o', '')
        elif f'{component_id} ' in string:
            value = string.replace(component_id, '')
        value = value.replace('= [', '')
        value = value.replace(']', '')
        value = value.replace(',', '')
        value = value.replace(' ', '')

        return value

    def get_command_for_solver_process(self, input_file_path, model_type, solver_name):
        solvers = ['xor_differential_one_solution',
                   'xor_linear_one_solution',
                   'deterministic_truncated_xor_differential_one_solution']
        write_model_to_file(self._model_constraints, input_file_path)
        if model_type in solvers:
            command = ['minizinc', '--solver-statistics', '--solver', solver_name, input_file_path]
        else:
            command = ['minizinc', '-a', '--solver-statistics', '--solver', solver_name, input_file_path]

        return command

    def get_mix_column_all_inputs(self, input_bit_positions_1, input_id_link_1, numb_of_inp_1):
        all_inputs = []
        for i in range(numb_of_inp_1):
            for j in range(len(input_bit_positions_1[i]) // self.word_size):
                all_inputs.append(f'{input_id_link_1[i]}'
                                  f'[{input_bit_positions_1[i][j * self.word_size] // self.word_size}]')

        return all_inputs

    def get_total_weight(self, string_total_weight):
        if not string_total_weight:
            total_weight = [0]
        elif string_total_weight is None:
            total_weight = None
        else:
            total_weight = [str(int(w)/100.0) for w in string_total_weight]

        return total_weight

    def parse_solver_information(self, output_to_parse, truncated):
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
            elif 'Trail weight' in string and not truncated:
                string_total_weight.append(float(string.replace("Trail weight = ", "")))
                components_values[f'solution{number_of_solutions}'] = {}
                number_of_solutions += 1
            elif '----------' in string and truncated:
                string_total_weight.append("0")
                components_values[f'solution{number_of_solutions}'] = {}
                number_of_solutions += 1
            elif 'UNSATISFIABLE' in string:
                string_total_weight = None
        total_weight = self.get_total_weight(string_total_weight)
        if number_of_solutions == 1:
            components_values = {}

        return components_values, memory, time, total_weight

    def _parse_solver_output(self, output_to_parse, truncated=False):
        """
        Parse solver solution (if needed).

        INPUT:

        - ``output_to_parse`` -- **list**; strings that represents the solver output
        - ``truncated`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import CpXorDifferentialTrailSearchModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, write_model_to_file
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
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
        components_values, memory, time, total_weight = self.parse_solver_information(output_to_parse, truncated)
        all_components = [*self._cipher.inputs, *self._cipher.get_all_components_ids()]
        for component_id in all_components:
            solution_number = 1
            for j, string in enumerate(output_to_parse):
                if f'{component_id} ' in string or f'{component_id}_i' in string or f'{component_id}_o' in string:
                    value = self.format_component_value(component_id, string)
                    component_solution = {}
                    self.set_component_solution_value(component_solution, truncated, value)
                    self.add_solution_to_components_values(component_id, component_solution, components_values, j,
                                                           output_to_parse, solution_number, string)
                elif '----------' in string:
                    solution_number += 1

        return time, memory, components_values, total_weight

    def set_component_solution_value(self, component_solution, truncated, value):
        if not truncated:
            bin_value = int(value, 2)
            hex_value = f'{bin_value:x}'
            hex_value = ('0' * (math.ceil(len(value) / 4) - len(hex_value))) + hex_value
            component_solution['value'] = hex_value
        else:
            component_solution['value'] = value

    def solve(self, model_type, solver_name=None):
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

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import CpXorDifferentialTrailSearchModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
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
        input_file_path = f'{cipher_name}_Cp_{model_type}_{solver_name}.mzn'
        command = self.get_command_for_solver_process(input_file_path, model_type, solver_name)
        solver_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        os.remove(input_file_path)
        if solver_process.returncode >= 0:
            solutions = []
            solver_output = solver_process.stdout.splitlines()
            if model_type in ['deterministic_truncated_xor_differential',
                              'deterministic_truncated_xor_differential_one_solution',
                              'impossible_xor_differential']:
                solve_time, memory, components_values, total_weight = self._parse_solver_output(solver_output, True)
            else:
                solve_time, memory, components_values, total_weight = self._parse_solver_output(solver_output)
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
                                                          solver_name, solver_output, total_weight)
            if model_type in ['xor_differential_one_solution',
                              'xor_linear_one_solution',
                              'deterministic_truncated_one_solution']:
                return solutions[0]
            else:
                return solutions

    def weight_constraints(self, weight):
        """
        Return a list of CP constraints that fix the total weight to a specific value.

        INPUT:

        - ``weight`` -- **integer**; a specific weight. If set to non-negative integer, fixes the XOR trail weight

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpModel(speck)
            sage: cp.weight_constraints(10)
            (['constraint weight = 1000;'], [])
        """
        cp_constraints = []
        if weight == 0 or weight == -1:
            cp_declarations = []
        else:
            cp_declarations = [f'constraint weight = {100 * weight};']

        return cp_declarations, cp_constraints

    @property
    def cipher(self):
        return self._cipher

    @property
    def cipher_id(self):
        return self._cipher.id

    @property
    def float_and_lat_values(self):
        return self._float_and_lat_values

    @property
    def model_constraints(self):
        """
        Return the model specified by ``model_type``.

        INPUT:

        - ``model_type`` -- **string**; the model to retrieve

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: cp = CpModel(speck)
            sage: cp.model_constraints()
            Traceback (most recent call last):
            ...
            ValueError: No model generated
        """
        if not self._model_constraints:
            raise ValueError('No model generated')
        return self._model_constraints
