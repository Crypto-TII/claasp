
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

from copy import deepcopy

from sage.crypto.sbox import SBox

from datetime import timedelta

from minizinc import Instance, Model, Solver, Status

from claasp.cipher_modules.component_analysis_tests import branch_number
from claasp.cipher_modules.models.cp.minizinc_utils import usefulfunctions
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary
from claasp.name_mappings import SBOX
from claasp.cipher_modules.models.cp.solvers import CP_SOLVERS_INTERNAL, CP_SOLVERS_EXTERNAL, MODEL_DEFAULT_PATH, SOLVER_DEFAULT

solve_satisfy = 'solve satisfy;'
constraint_type_error = 'Constraint type not defined'


class MznModel:

    def __init__(self, cipher, window_size_list=None, probability_weight_per_round=None, sat_or_milp='sat'):
        self._cipher = cipher
        self.initialise_model()
        if sat_or_milp not in ['sat', 'milp']:
            raise ValueError("Allowed value for sat_or_milp parameter is either sat or milp")

        self.sat_or_milp = sat_or_milp
        if self.sat_or_milp == "sat":
            self.data_type = "bool"
            self.true_value = "true"
            self.false_value = "false"
        else:
            self.data_type = "0..1"
            self.true_value = "1"
            self.false_value = "0"

        self.probability_vars = []
        self.carries_vars = []
        self.mzn_comments = []
        self.intermediate_constraints_array = []
        self.mzn_output_directives = []
        self.mzn_carries_output_directives = []
        self.input_postfix = "x"
        self.output_postfix = "y"
        self.window_size_list = window_size_list
        self.probability_weight_per_round = probability_weight_per_round
        self.carries_vars = []
        if probability_weight_per_round and len(probability_weight_per_round) != self._cipher.number_of_rounds:
            raise ValueError("probability_weight_per_round size must be equal to cipher_number_of_rounds")

        self.probability_modadd_vars_per_round = [[] for _ in range(self._cipher.number_of_rounds)]

        if window_size_list and len(window_size_list) != self._cipher.number_of_rounds:
            raise ValueError("window_size_list size must be equal to cipher_number_of_rounds")

        
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
        self._model_prefix = ['include "globals.mzn";', f'{usefulfunctions.MINIZINC_USEFUL_FUNCTIONS}']

    def add_comment(self, comment):
        """
        Write a 'comment' at the beginning of the model.

        INPUT:

        - ``comment`` -- **string**; string with the comment to be added
        """
        self.mzn_comments.append("% " + comment)

    def add_constraint_from_str(self, str_constraint):
        self._model_constraints.append(str_constraint)

    def add_output_comment(self, comment):
        self.mzn_output_directives.append(f'output [\"Comment: {comment}\", \"\\n\"];')

    def add_solutions_from_components_values(self, components_values, memory, model_type, solutions, solve_time,
                                             solver_name, solver_output, total_weight, solve_external):
        for i in range(len(total_weight)):
            solution = convert_solver_solution_to_dictionary(
                self._cipher,
                model_type,
                solver_name,
                solve_time,
                memory,
                components_values[f'solution{i + 1}'],
                total_weight[i])
            if solve_external:
                if 'UNSATISFIABLE' in solver_output[0]:
                    solution['status'] = 'UNSATISFIABLE'
                else:
                    solution['status'] = 'SATISFIABLE'
            else:
                if solver_output.status not in [Status.SATISFIED, Status.ALL_SOLUTIONS, Status.OPTIMAL_SOLUTION]:
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

    def add_solution_to_components_values_internal(self, component_solution, components_values, component_weight,
                                          solution_number, component):
        component_solution['weight'] = component_weight
        components_values[f'solution{solution_number}'][f'{component}'] = component_solution

    def build_mix_column_truncated_table(self, component):
        """
        Return a model that generates the list of possible input/output  couples for the given mix column.

        INPUT:

        - ``component`` -- **Component object**; the mix column component in Cipher

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = MznModel(aes)
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
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: midori = MidoriBlockCipher()
            sage: cp = MznModel(midori)
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

            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznModel(speck)
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

    def fix_variables_value_constraints_for_ARX(self, fixed_variables=[]):
        """
        Return a list of constraints that fix the input variables to a specific value.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model_arx_optimized import MznXorDifferentialModelARXOptimized
            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=1)
            sage: minizinc = MznXorDifferentialModelARXOptimized(raiden)
            sage: minizinc.build_xor_differential_trail_model()
            sage: fixed_variables = [{
            ....:     'component_id': 'key',
            ....:     'constraint_type': 'equal',
            ....:     'bit_positions': [0, 1, 2, 3],
            ....:     'bit_values': [0, 1, 0, 1]
            ....: }]
            sage: minizinc.fix_variables_value_constraints_for_ARX(fixed_variables)[0]
            'constraint key_y0 = 0;'

            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': [0, 1, 2, 3],
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: minizinc.fix_variables_value_constraints_for_ARX(fixed_variables)[0]
            'constraint plaintext_y0+plaintext_y1+plaintext_y2+plaintext_y3>0;'
        """
        def equal_operator(constraints_, fixed_variables_object_):
            component_name = fixed_variables_object_["component_id"]
            for i in range(len(fixed_variables_object_["bit_positions"])):
                bit_position = fixed_variables_object_["bit_positions"][i]
                bit_value = fixed_variables_object_["bit_values"][i]
                constraints_.append(f'constraint {component_name}_y{bit_position} = {bit_value};')
                if 'intermediate_output' in component_name or 'cipher_output' in component_name:
                    constraints_.append(f'constraint {component_name}_x{bit_position}'
                                        f'='
                                        f'{bit_value};')

        def sum_operator(constraints_, fixed_variables_object_):
            component_name = fixed_variables_object_["component_id"]
            bit_positions = []
            for i in range(len(fixed_variables_object_["bit_positions"])):
                bit_position = fixed_variables_object_["bit_positions"][i]
                bit_var_name_position = f'{component_name}_y{bit_position}'
                bit_positions.append(bit_var_name_position)
            constraints_.append(f'constraint {"+".join(bit_positions)}'
                                f'{fixed_variables_object_["operator"]}'
                                f'{fixed_variables_object_["value"]};')

        constraints = []

        for fixed_variables_object in fixed_variables:
            if fixed_variables_object["constraint_type"] == "equal":
                equal_operator(constraints, fixed_variables_object)
            elif fixed_variables_object["constraint_type"] == "sum":
                sum_operator(constraints, fixed_variables_object)

        return constraints

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

    def get_command_for_solver_process(self, input_file_path, model_type, solver_name, num_of_processors, timelimit):
        solvers = ['xor_differential_one_solution',
                   'xor_linear_one_solution',
                   'deterministic_truncated_xor_differential_one_solution',
                   'impossible_xor_differential_one_solution',
                   'differential_pair_one_solution',
                   'evaluate_cipher']
        write_model_to_file(self._model_constraints, input_file_path)
        for i in range(len(CP_SOLVERS_EXTERNAL)):
            if solver_name == CP_SOLVERS_EXTERNAL[i]['solver_name']:
                command_options = deepcopy(CP_SOLVERS_EXTERNAL[i])
        command_options['keywords']['command']['input_file'].append(input_file_path)
        if model_type not in solvers:
            command_options['keywords']['command']['options'].insert(0, '-a')
        if num_of_processors is not None:
            command_options['keywords']['command']['options'].insert(0, f'-p {num_of_processors}')
        if timelimit is not None:
            command_options['keywords']['command']['options'].append('--time-limit')
            command_options['keywords']['command']['options'].append(str(timelimit))
        command = []
        for key in command_options['keywords']['command']['format']:
            command.extend(command_options['keywords']['command'][key])
            
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

    def output_probability_per_round(self):
        for mzn_probability_modadd_vars in self.probability_modadd_vars_per_round:
            mzn_probability_vars_per_round = "++".join(mzn_probability_modadd_vars)
            self.mzn_output_directives.append(f'output ["\\n"++"Probability {mzn_probability_vars_per_round}:'
                                              f' "++show(sum({mzn_probability_vars_per_round}))++"\\n"];')

    def parse_solver_information(self, output_to_parse, truncated=False, solve_external = True):

        memory = -1
        time = -1
        string_total_weight = []
        components_values = {}
        number_of_solutions = 1
        if solve_external:
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
        if number_of_solutions == 1:
            components_values = {}
        total_weight = self.get_total_weight(string_total_weight)

        if truncated:
            return components_values, memory, time
        return components_values, memory, time, total_weight

    def _parse_solver_output(self, output_to_parse, model_type, truncated = False, solve_external = False, solver_name = SOLVER_DEFAULT):
        """
        Parse solver solution (if needed).

        INPUT:

        - ``output_to_parse`` -- **list**; strings that represents the solver output
        - ``truncated`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import MznXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, write_model_to_file
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: cp.build_xor_differential_trail_model(-1, fixed_variables)
            sage: write_model_to_file(cp._model_constraints,'doctesting_file.mzn')
            sage: command = ['minizinc', '--solver-statistics', '--solver', 'Chuffed', 'doctesting_file.mzn']
            sage: import subprocess
            sage: solver_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
            sage: os.remove('doctesting_file.mzn')
            sage: solver_output = solver_process.stdout.splitlines()
            sage: cp._parse_solver_output(solver_output, model_type = 'xor_differential_one_solution', solve_external = True) # random
            (0.018,
             ...
             'cipher_output_3_12': {'value': '0', 'weight': 0}}},
             ['0'])
        """
        def set_solution_values_internal(solution):
            components_values = {}
            values = solution.__dict__['_output_item'].splitlines()
            total_weight = 0
            for i in range(len(values)):
                curr_val = values[i]
                if 'Trail weight' in curr_val:
                    total_weight = str(int(curr_val[curr_val.index('=') + 2:])/100.0)
                elif '[' in curr_val:
                    component_id = curr_val[:curr_val.index('=') - 1]
                    value = ''.join(curr_val[curr_val.index('[') + 1:-1].split(', '))
                    components_values[component_id] = {}
                    self.set_component_solution_value(components_values[component_id], truncated, value)
                    if '=' not in values[i+1]:
                        components_values[component_id]['weight'] = float(values[i+1])
                    else:
                        components_values[component_id]['weight'] = 0
            return components_values, total_weight
        
        if solve_external:
            if truncated:
                components_values, memory, time = self.parse_solver_information(output_to_parse, truncated, solve_external)
            else:
                components_values, memory, time, total_weight = self.parse_solver_information(output_to_parse, truncated, solve_external)
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
        else:
            if 'solveTime' in output_to_parse.statistics:
                time = output_to_parse.statistics['solveTime'].total_seconds()
            else:
                time = output_to_parse.statistics['time'].total_seconds()
            if 'trailMem' in output_to_parse.statistics:
                memory = output_to_parse.statistics['trailMem']
            else:
                memory = '-1'
            if output_to_parse.status not in [Status.SATISFIED, Status.ALL_SOLUTIONS, Status.OPTIMAL_SOLUTION]:
                solutions = convert_solver_solution_to_dictionary(self._cipher, model_type, solver_name, time, memory, {}, '0')
                solutions['status'] = 'UNSATISFIABLE'
            else:
                if output_to_parse.statistics['nSolutions'] == 1 or type(output_to_parse.solution) != list:
                    components_values, total_weight = set_solution_values_internal(output_to_parse.solution)
                    solutions = convert_solver_solution_to_dictionary(self._cipher, model_type, solver_name, time, memory, components_values, total_weight)
                    if output_to_parse.status not in [Status.SATISFIED, Status.ALL_SOLUTIONS, Status.OPTIMAL_SOLUTION]:
                        solutions['status'] = 'UNSATISFIABLE'
                    else:
                        solutions['status'] = 'SATISFIABLE'
                else:
                    solutions = []
                    for solution in output_to_parse.solution:
                        components_values, total_weight = set_solution_values_internal(solution)
                        solution = convert_solver_solution_to_dictionary(self._cipher, model_type, solver_name, time, memory, components_values, total_weight)
                        if output_to_parse.status not in [Status.SATISFIED, Status.ALL_SOLUTIONS, Status.OPTIMAL_SOLUTION]:
                            solution['status'] = 'UNSATISFIABLE'
                        else:
                            solution['status'] = 'SATISFIABLE'
                        solutions.append(solution)
            return solutions
                    
        if truncated:
            return time, memory, components_values
        return time, memory, components_values, total_weight

    def set_component_solution_value(self, component_solution, truncated, value):
        if not truncated:
            bin_value = int(value, 2)
            hex_value = f'{bin_value:x}'
            hex_value = ('0x' + '0' * (math.ceil(len(value) / 4) - len(hex_value))) + hex_value
            component_solution['value'] = hex_value
        else:
            component_solution['value'] = value

    def solve(self, model_type, solver_name=SOLVER_DEFAULT, solve_external=False, timeout_in_seconds_=None,
              processes_=None, nr_solutions_=None, random_seed_=None,
              all_solutions_=False, intermediate_solutions_=False,
              free_search_=False, optimisation_level_=None):
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

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import MznXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', list(range(64)), integer_to_bit_list(0, 64, 'little')), set_fixed_variables('plaintext', 'not_equal', list(range(32)), integer_to_bit_list(0, 32, 'little'))]
            sage: cp.build_xor_differential_trail_model(-1, fixed_variables)
            sage: cp.solve('xor_differential', 'chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r4',
               ...
              'total_weight': '5.0'}]
        """
        truncated = False
        if model_type in ['deterministic_truncated_xor_differential',
                          'deterministic_truncated_xor_differential_one_solution',
                          'impossible_xor_differential',
                          'impossible_xor_differential_one_solution',
                          'impossible_xor_differential_attack']:
            truncated = True
        solutions = []
        if solve_external:
            cipher_name = self.cipher_id
            input_file_path = f'{MODEL_DEFAULT_PATH}/{cipher_name}_Mzn_{model_type}_{solver_name}.mzn'
            command = self.get_command_for_solver_process(
                input_file_path, model_type, solver_name, processes_, timeout_in_seconds_
            )
            solver_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
            os.remove(input_file_path)
            if solver_process.returncode >= 0:
                solver_output = solver_process.stdout.splitlines()
        else:
            constraints = self._model_constraints
            mzn_model_string = "\n".join(constraints)
            solver_name_mzn = Solver.lookup(solver_name)
            bit_mzn_model = Model()
            bit_mzn_model.add_string(mzn_model_string)
            instance = Instance(solver_name_mzn, bit_mzn_model)
            if processes_ != None and timeout_in_seconds_ != None:
                solver_output = instance.solve(processes=processes_, timeout=timedelta(seconds=int(timeout_in_seconds_)),
                                    nr_solutions=nr_solutions_, random_seed=random_seed_, all_solutions=all_solutions_,
                                    intermediate_solutions=intermediate_solutions_, free_search=free_search_,
                                    optimisation_level=optimisation_level_)
            else:
                solver_output = instance.solve(nr_solutions=nr_solutions_, random_seed=random_seed_, all_solutions=all_solutions_,
                                    intermediate_solutions=intermediate_solutions_, free_search=free_search_,
                                    optimisation_level=optimisation_level_)
            return self._parse_solver_output(solver_output, model_type, truncated = truncated, solve_external = solve_external, solver_name=solver_name)
        if truncated:
            solve_time, memory, components_values = self._parse_solver_output(solver_output, model_type, truncated = True, solve_external = solve_external)
            total_weight = 0
        else:
            solve_time, memory, components_values, total_weight = self._parse_solver_output(solver_output, model_type, solve_external = solve_external, solver_name=solver_name)
        if components_values == {}:
            solution = convert_solver_solution_to_dictionary(self._cipher, model_type, solver_name,
                                                             solve_time, memory,
                                                             components_values, total_weight)
            if '=====UNSATISFIABLE=====' in solver_output:
                solution['status'] = 'UNSATISFIABLE'
            else:
                solution['status'] = 'SATISFIABLE'
            solutions.append(solution)
        else:
            self.add_solutions_from_components_values(components_values, memory, model_type, solutions, solve_time,
                                                      solver_name, solver_output, total_weight, solve_external)
        if model_type in ['xor_differential_one_solution',
                          'xor_linear_one_solution',
                          'deterministic_truncated_one_solution',
                          'impossible_xor_differential_one_solution']:
            return solutions[0]
        else:
            return solutions
                
    def solve_for_ARX(self, solver_name=None, timeout_in_seconds_=30,
              processes_=4, nr_solutions_=None, random_seed_=None,
              all_solutions_=False, intermediate_solutions_=False,
              free_search_=False, optimisation_level_=None):
        """
        Solve the model passed in `str_model_path` by using `MiniZinc` and `str_solver``.

        INPUT:

            - ``model_type`` -- **string**; the type of the model that has been solved
            - ``solver_name`` -- **string** (default: `None`); name of the solver to be used together with MiniZinc
            - ``timeout_in_seconds_`` -- **integer** (default: `30`); time in seconds to interrupt the solving process
            - ``processes_`` -- **integer** (default: `4`); set the number of processes the solver can use. (Only
              available when the ``-p`` flag is supported by the solver)
            - ``nr_solutions_`` -- **integer** (default: `None`); the requested number of solution. (Only available on
              satisfaction problems and when the ``-n`` flag is supported by the solver)
            - ``random_seed_`` -- **integer** (default: `None`); set the random seed for solver. (Only available when
              the ``-r`` flag is supported by the solver)
            - ``intermediate_solutions_`` -- **boolean** (default: `False`); request the solver to output any
              intermediate solutions that are found during the solving process. (Only available on optimisation
              problems and when the ``-a`` flag is supported by the solver)
            - ``all_solutions_`` -- **boolean** (default: `False`); request to solver to find all solutions. (Only
              available on satisfaction problems and when the ``-a`` flag is supported by the solver)
            - ``free_search`` -- **boolean** (default: `False`); allow the solver to ignore the search definition within
              the instance (Only available when the ``-f`` flag is supported by the solver)
            - ``optimisation_level_`` -- **integer** (default: `None`); set the MiniZinc compiler optimisation level

              - 0: Disable optimisation
              - 1: Single pass optimisation (default)
              - 2: Flatten twice to improve flattening decisions
              - 3: Perform root-node-propagation
              - 4: Probe bounds of all variables at the root node
              - 5: Probe values of all variables at the root node

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model_arx_optimized import MznXorDifferentialModelARXOptimized
            sage: speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
            sage: minizinc = MznXorDifferentialModelARXOptimized(speck)
            sage: bit_positions = [i for i in range(speck.output_bit_size)]
            sage: bit_positions_key = list(range(64))
            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions,
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: fixed_variables.append({ 'component_id': 'key',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions_key,
            ....:     'operator': '=',
            ....:     'value': '0' })
            sage: minizinc.build_xor_differential_trail_model(-1, fixed_variables)
            sage: result = minizinc.solve_for_ARX('Xor')
            sage: result.statistics['nSolutions']
            1
        """
        constraints = self._model_constraints
        variables = self._variables_list
        mzn_model_string = "\n".join(constraints) + "\n".join(variables)
        solver_name_mzn = Solver.lookup(solver_name)
        bit_mzn_model = Model()
        bit_mzn_model.add_string(mzn_model_string)
        instance = Instance(solver_name_mzn, bit_mzn_model)
        if processes_ != None and timeout_in_seconds_ != None:
            result = instance.solve(processes=processes_, timeout=timedelta(seconds=int(timeout_in_seconds_)),
                                nr_solutions=nr_solutions_, random_seed=random_seed_, all_solutions=all_solutions_,
                                intermediate_solutions=intermediate_solutions_, free_search=free_search_,
                                optimisation_level=optimisation_level_)
        else:
            result = instance.solve(nr_solutions=nr_solutions_, random_seed=random_seed_, all_solutions=all_solutions_,
                                intermediate_solutions=intermediate_solutions_, free_search=free_search_,
                                optimisation_level=optimisation_level_)

        return result

    def solver_names(self, verbose = False):
        if not verbose:
            print('Internal CP solvers:')
            print('solver brand name | solver name')
            for i in range(len(CP_SOLVERS_INTERNAL)):
                print(f'{CP_SOLVERS_INTERNAL[i]["solver_brand_name"]} | {CP_SOLVERS_INTERNAL[i]["solver_name"]}')
            print('\n')
            print('External CP solvers:')
            print('solver brand name | solver name')
            for i in range(len(CP_SOLVERS_EXTERNAL)):
                print(f'{CP_SOLVERS_EXTERNAL[i]["solver_brand_name"]} | {CP_SOLVERS_EXTERNAL[i]["solver_name"]}')
        else:
            print('Internal CP solvers:')
            print(CP_SOLVERS_INTERNAL)
            print('\n')
            print('External CP solvers:')
            print(CP_SOLVERS_EXTERNAL)

    def weight_constraints(self, weight):
        """
        Return a list of CP constraints that fix the total weight to a specific value.

        INPUT:

        - ``weight`` -- **integer**; a specific weight. If set to non-negative integer, fixes the XOR trail weight

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznModel(speck)
            sage: cp.weight_constraints(10)
            (['constraint weight = 1000;'], [])
        """
        cp_constraints = []
        if weight == 0 or weight == -1:
            cp_declarations = []
        else:
            cp_declarations = [f'constraint weight = {100 * weight};']

        return cp_declarations, cp_constraints

    def write_minizinc_model_to_file(self, file_path, prefix=""):
        """
        Write the MiniZinc model into a file inside file_path.

        INPUT:

        - ``file_path`` -- **string**; the path of the file that will contain the model
        - ``prefix`` -- **str** (default: ``)
        """
        model_string = "\n".join(self.mzn_comments) + "\n".join(self._variables_list) +  \
                       "\n".join(self._model_constraints) + "\n".join(self.mzn_output_directives) + \
                       "\n".join(self.mzn_carries_output_directives)
        if prefix == "":
            filename = f'{file_path}/{self.cipher_id}_mzn_{self.sat_or_milp}.mzn'
        else:
            filename = f'{file_path}/{prefix}_{self.cipher_id}_mzn_{self.sat_or_milp}.mzn'

        f = open(filename, "w")
        f.write(model_string)
        f.close()

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
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: cp = MznModel(speck)
            sage: cp.model_constraints()
            Traceback (most recent call last):
            ...
            ValueError: No model generated
        """
        if not self._model_constraints:
            raise ValueError('No model generated')
        return self._model_constraints
