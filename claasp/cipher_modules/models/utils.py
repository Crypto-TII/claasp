
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
import math
from copy import deepcopy

import numpy as np

from claasp.name_mappings import CONSTANT, CIPHER_OUTPUT, INTERMEDIATE_OUTPUT, WORD_OPERATION, LINEAR_LAYER, SBOX, \
    MIX_COLUMN, \
    INPUT_KEY, INPUT_PLAINTEXT, INPUT_MESSAGE, INPUT_STATE
from claasp.utils.utils import get_k_th_bit


def add_arcs(arcs, component, curr_input_bit_ids, input_bit_size, intermediate_output_arcs, previous_output_bit_ids):
    for i in range(input_bit_size):
        if component.type == INTERMEDIATE_OUTPUT:
            arcs_to_add = arcs[previous_output_bit_ids[i]] if previous_output_bit_ids[i] in arcs else []
            intermediate_output_arcs[component.id][curr_input_bit_ids[i]] = \
                [previous_output_bit_ids[i]] + arcs_to_add
        else:
            if previous_output_bit_ids[i] not in arcs:
                arcs[previous_output_bit_ids[i]] = []
            arcs[previous_output_bit_ids[i]].append(curr_input_bit_ids[i])


def check_if_implemented_component(component):
    component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                       SBOX, MIX_COLUMN, WORD_OPERATION]
    operation = component.description[0]
    operation_types = ['AND', 'OR', 'MODADD', 'MODSUB', 'NOT', 'ROTATE', 'SHIFT', 'XOR']
    if component.type not in component_types or \
            (component.type == WORD_OPERATION and operation not in operation_types):
        print(f'{component.id} not yet implemented')
        return False
    return True


def convert_solver_solution_to_dictionary(cipher, model_type, solver_name, solve_time, memory,
                                          components_values, total_weight):
    """
    Return a dictionary that represents the solution obtained from the solver.

    INPUT:

    - ``cipher_id`` -- **string**; the cipher id
    - ``model_type`` -- **string**; the type of the model that has been solved
    - ``solver_name`` -- **string**; the solver used to get the solution
    - ``solve_time`` -- **float**; the time (in seconds) consumed by the solver finding the solution
    - ``memory`` -- **float**; the memory (in MB) consumed by the solver finding the solution
    - ``components_values`` -- **dictionary**; each key of the dictionary is the component id, each value is a
      dictionary whose keys are ``value`` and ``weight``
    - ``total_weight`` -- **integer**; representing the total weight

    .. SEEALSO::

        :py:meth:`~cipher_modules.models.utils.set_component_value_weight_sign`

    EXAMPLES::

        sage: from claasp.cipher_modules.models.utils import convert_solver_solution_to_dictionary
        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: speck = SpeckBlockCipher(number_of_rounds=4)
        sage: convert_solver_solution_to_dictionary(speck.id, 'xor_differential', 'z3', 0.239, 175.5, [], 0)
        {'cipher': 'speck_p32_k64_o32_r4',
         'components_values': [],
         'memory_megabytes': 175.500000000000,
         'model_type': 'xor_differential',
         'solver_name': 'z3',
         'solving_time_seconds': 0.239000000000000,
         'total_weight': 0}
    """
    return {
        'cipher': cipher,
        'model_type': model_type,
        'solver_name': solver_name,
        'solving_time_seconds': solve_time,
        'memory_megabytes': memory,
        'components_values': components_values,
        'total_weight': total_weight
    }


def create_directory(file_path, library_path):
    folder_path, file_name = os.path.split(file_path)
    folder_path = os.path.join(library_path, folder_path)
    if not os.path.isdir(folder_path):
        os.makedirs(folder_path)


def get_library_path():
    library_path = os.path.dirname(os.path.abspath(__file__)).split(f'claasp{os.sep}')[0]

    return library_path + 'claasp'


def get_previous_output_bit_ids(input_bit_positions, input_id_links, format_func):
    previous_output_bit_ids = []
    for id_link, bit_positions in zip(input_id_links, input_bit_positions):
        previous_output_bit_ids.extend(
            [format_func((id_link, f'{position}', 'o')) for position in bit_positions])

    return previous_output_bit_ids


def integer_to_bit_list(int_value, list_length, endianness='little'):
    """
    Return a list that contains the binary value for each bit position.

    INPUT:

    - ``int_value`` -- **integer**; the value to convert in binary
    - ``list_length`` -- **integer**; the value representing the desired length of the output list
    - ``endianness`` -- **string** (default: `little`); the endianess of the list

      * ``endianess='big'``, the bit list will be returned with the MSB indexed by 0
      * ``endianess='little'``, the bit list will be returned with the LSB indexed by 0

    EXAMPLES::

        sage: from claasp.cipher_modules.models.utils import integer_to_bit_list
        sage: integer_to_bit_list(5, 5, 'big')
        [0, 0, 1, 0, 1]
    """
    binary_value = [int_value >> i & 1 for i in range(list_length)]
    if endianness == 'big':
        return binary_value[::-1]

    return binary_value


def print_components_values(solution):
    """
    Print the dict of component values in standard format.

    .. SEEALSO::

        :py:meth:`~cipher_modules.models.utils.set_component_value_weight_sign`

    INPUT:

    - ``solution`` -- **dictionary**; the solution as given by :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

    EXAMPLES::

        sage: from claasp.cipher_modules.models.utils import print_components_values
        sage: print_components_values({
        ....:     'components_values': {
        ....:         'plaintext': {
        ....:             'value': '0x1234',
        ....:             'weight': 0
        ....:         },
        ....:         'key': {
        ....:             'value': '0xabcd',
        ....:             'weight': 7
        ....:         }
        ....:     }
        ....: })
        ┌───────────────────────────┬──────────────────────────────────────────┬────────┐
        │ COMPONENT ID              │ VALUE                                    │ WEIGHT │
        ├───────────────────────────┼──────────────────────────────────────────┼────────┤
        │ plaintext                 │ 0x1234                                   │ -      │
        ├───────────────────────────┼──────────────────────────────────────────┼────────┤
        │ key                       │ 0xabcd                                   │ 7      │
        └───────────────────────────┴──────────────────────────────────────────┴────────┘
    """

    def line_formatter(component_id):
        value = solution['components_values'][component_id]['value']
        weight = str(solution['components_values'][component_id]['weight'])
        weight_cell = f'{"-": <6}'
        if weight != '0':
            weight_cell = f'{weight: <{7 - len(weight)}}'
        line = f'│ {component_id: <25} │ {value: <40} │ {weight_cell} │'
        return line

    horizontal_separator = f'├{"─" * 27}┼{"─" * 42}┼{"─" * 8}┤'
    # ------- header
    print(f'┌{"─" * 27}┬{"─" * 42}┬{"─" * 8}┐')
    print(f'│ {"COMPONENT ID": <26}│ {"VALUE": <41}│ {"WEIGHT"} │')
    print(horizontal_separator)
    # ------- body
    component_ids = list(solution['components_values'].keys())
    for component_id in component_ids[:-1]:
        print(line_formatter(component_id))
        print(horizontal_separator)
    last_component_id = component_ids[-1]
    print(line_formatter(last_component_id))
    print(f'└{"─" * 27}┴{"─" * 42}┴{"─" * 8}┘')


def set_component_value_weight_sign(value, weight=0, sign=1):
    """
    Return a dictionary that represents the solution for one component of the cipher.

    INPUT:

    - ``value`` -- **string**; hexadecimal representation (e.g. ``'0x1234'``) that represents the output of the
      component
    - ``weight`` -- **integer** (default: `0`); the weight of the component (remark: if different from 0, the current
      component is non-linear operation)
    - ``sign`` -- **integer** (default: `1`); the sign of the weight of the component (either 1 or -1)

    EXAMPLES::

        sage: from claasp.cipher_modules.models.utils import set_component_value_weight_sign
        sage: set_component_value_weight_sign('0x0000', 0, 1)
        {'sign': 1, 'value': '0x0000', 'weight': 0}
    """
    return {
        'value': value,
        'weight': weight,
        'sign': sign
    }


def set_component_solution(value, weight=None, sign=None):
    """
    Return a dictionary that represents the solution for one component of the cipher.

    INPUT:

    - ``value`` -- **string**; hexadecimal representation (e.g. ``'abcd1234'``) that represents the output of the
      component
    - ``weight`` -- **integer** (default: `None`); the weight of the component
    - ``sign`` -- **integer** (default: `None`); the sign of the weight of the component (either 1 or -1)

    EXAMPLES::

        sage: from claasp.cipher_modules.models.utils import set_component_solution
        sage: set_component_solution('abcd1234', 0, 1)
        {'sign': 1, 'value': 'abcd1234', 'weight': 0}
    """
    component_solution = {'value': value}
    if weight is not None:
        component_solution['weight'] = weight
    if sign is not None:
        component_solution['sign'] = sign
    return component_solution


def set_fixed_variables(component_id, constraint_type, bit_positions, bit_values):
    """
    Return a dictionary.

    The dictionary has the information needed to fix the output of a component to a specific value or some bits of the
    output to specific values.

    INPUT:

    - ``component_id`` -- **string**; the id of the component
    - ``constraint_type`` -- **string**; the type of the constraint

      * ``'equal'``, the constraints will fix ``bit_values`` for the component specified by ``component_id``
      * ``'not_equal'``, the constraints will avoid at least one of the ``bit_values`` for the component specified by
        ``component_id``
    - ``bit_positions`` -- **list of int**; the positions of the bits to be fixed
    - ``bit_values`` -- **list of int**; the values of each bit. If ``len(bit_values) < len(bit_positions)`` the
      bit_values list will be padded with '0' values, otherwise bit_values will be truncated to match the
      ``bit_positions`` list length

    EXAMPLES::

        sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
        sage: set_fixed_variables('key', 'equal', list(range(4)), integer_to_bit_list(5, 4, 'little'))
        {'bit_positions': [0, 1, 2, 3],
         'bit_values': [1, 0, 1, 0],
         'component_id': 'key',
         'constraint_type': 'equal'}
    """
    return {
        'component_id': component_id,
        'constraint_type': constraint_type,
        'bit_positions': bit_positions,
        'bit_values': bit_values
    }


def write_model_to_file(model_to_write, file_name):
    """
    Write the solver model into a file inside the current directory.

    .. NOTE::

        This file can be deleted once the solver has finished its computation.

    INPUT:

    - ``model_to_write`` -- **list**; the model
    - ``file_name`` -- **string**; the path of the file that will contain the model. The suggested format for the name
      of the file is: [graph_representation_of_the_cipher]_[solver_type].txt (e.g. speck32_64_r22_sat.txt)

    OUTPUT:

    - This method does not return anything, but it creates a file with the specified model as a string in it

    EXAMPLES::

        sage: from claasp.cipher_modules.models.utils import write_model_to_file
        sage: file_name = 'claasp/cipher_modules/models/model_file.txt'
        sage: write_model_to_file(['xor_differential', 'xor_linear'], file_name)
        sage: os.remove(file_name)
    """
    with open(file_name, 'w') as output_file:
        output_file.write('\n'.join(model_to_write) + '\n')
        output_file.close()


def write_solution_into_a_file(file_path, solution_to_write):
    original_stdout = sys.stdout  # Save a reference to the original standard output
    with open(file_path, 'w') as output_file:
        sys.stdout = output_file  # Change the standard output to the file we created.
        print("result = {")
        for key, value in solution_to_write.items():
            print(f"    {repr(key)}: {repr(value)},")
        print("}")
    sys.stdout = original_stdout  # Reset the standard output to its original value


def write_solution_to_file(solution_to_write, file_path):
    """
    Write the solver solution into a file.

    INPUT:

    - ``solution_to_write`` -- **dictionary**; the solution in standard format
    - ``file_path`` -- **string**; the entire path of the file that will contain the solution

    .. SEEALSO::

        :py:meth:`~cipher_modules.models.utils.convert_solver_solution_to_dictionary`

    .. NOTE::

        The ``file_path`` *should* be composed like this:
        claasp/previous_results/cipher_name/solver_type/cipher_id_solver_name.py
        E.g. claasp/previous_results/speck/sat/speck32_64_r22_cryptominisat.py

    OUTPUT:

    - This method does not return anything, but it creates a file with a solution of a solver

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import (convert_solver_solution_to_dictionary,
        ....: write_solution_to_file)
        sage: speck = SpeckBlockCipher(number_of_rounds=4)
        sage: file_name = 'claasp/previous_results/speck/sat/speck32_64_r22_cryptominisat.py'
        sage: dict = convert_solver_solution_to_dictionary(speck.id, 'xor_differential', 'z3', 0.239, 175.5, [], 0)
        sage: write_solution_to_file(dict, file_name) # doctest: +SKIP
        sage: os.remove(file_name) # doctest: +SKIP
    """
    library_path = get_library_path()
    if os.sep in file_path:
        create_directory(file_path, library_path)
    write_solution_into_a_file(file_path, solution_to_write)


def to_bias_for_xor_linear_trail(cipher, solution):
    """
    Return the trail of ``solution`` but with the weights corresponding to the bias.

    The value returned is a solution in standard format.

    INPUT:

    - ``solution`` -- **dictionary**; a trail found with :py:meth:`~find_lowest_weight_xor_linear_trail`

    EXAMPLES::

        sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, to_bias_for_xor_linear_trail
        sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4).remove_key_schedule()
        sage: milp = MilpXorLinearModel(speck)
        sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not equal',
        ....: bit_positions=range(32), bit_values=integer_to_bit_list(0x0, 32, 'big'))
        sage: trail = milp.find_lowest_weight_xor_linear_trail([plaintext]) # long
        ...

        sage: to_bias_for_xor_linear_trail(speck, trail) # random
        {'building_time_seconds': 0.06306815147399902,
         'cipher_id': 'speck_p32_k64_o32_r4',
         ...
         'measure': 'bias',
         ...
         'total_weight': 4.0}
    """
    if solution.get('measure') in [None, 'correlation']:
        return to_bias_for_correlation_measure(cipher, solution)

    if solution.get('measure') == 'probability':
        return to_bias_for_probability_measure(cipher, solution)

    return deepcopy(solution)


def to_bias_for_correlation_measure(cipher, solution):
    solution_with_bias = deepcopy(solution)
    solution_with_bias['measure'] = 'bias'
    solution_with_bias['total_weight'] += 1
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_bias['components_values'][component.id + suffix]['weight']:
                solution_with_bias['components_values'][component.id + suffix]['weight'] += 1

    return solution_with_bias


def to_bias_for_probability_measure(cipher, solution):
    solution_with_bias = deepcopy(solution)
    solution_with_bias['measure'] = 'bias'
    solution_with_bias['total_weight'] = \
        round(-math.log(2 ** (-solution_with_bias['total_weight']) - 1 / 2., 2), 1)
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_bias['components_values'][component.id + suffix]['weight']:
                solution_with_bias['components_values'][component.id + suffix]['weight'] = \
                    round(-math.log(2 ** (-solution_with_bias['components_values'][
                        component.id + suffix]['weight']) - 1 / 2., 2), 1)

    return solution_with_bias


def to_probability_for_xor_linear_trail(cipher, solution):
    """
    Return the trail of ``solution`` but with the weights corresponding to the probability.

    The value returned is a solutions in standard format.

    INPUT:

    - ``solution`` -- **dictionary**; a trail found with :py:meth:`~find_lowest_weight_xor_linear_trail`

    EXAMPLES::

        sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, to_probability_for_xor_linear_trail
        sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4).remove_key_schedule()
        sage: milp = MilpXorLinearModel(speck)
        sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not equal',
        ....: bit_positions=range(32), bit_values=integer_to_bit_list(0x0, 32, 'big'))
        sage: trail = milp.find_lowest_weight_xor_linear_trail([plaintext])
        ...

        sage: to_probability_for_xor_linear_trail(speck, trail) # random
        {'building_time_seconds': 0.13295412063598633,
         'cipher_id': 'speck_p32_k64_o32_r4',
         ...
         'measure': 'probability',
         ...
         'total_weight': 0.83}
    """
    if solution.get('measure') in [None, 'correlation']:
        return to_probability_for_correlation_measure(cipher, solution)

    elif solution.get('measure') == 'bias':
        return to_probability_for_bias_measure(cipher, solution)

    return deepcopy(solution)


def to_probability_for_correlation_measure(cipher, solution):
    solution_with_proba = deepcopy(solution)
    solution_with_proba['measure'] = 'probability'
    solution_with_proba['total_weight'] = \
        round(-math.log((2 ** (-solution_with_proba['total_weight']) + 1) / 2., 2), 3)
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_proba['components_values'][component.id + suffix]['weight']:
                solution_with_proba['components_values'][component.id + suffix]['weight'] = \
                    round(-math.log((2 ** (-solution_with_proba['components_values'][
                        component.id + suffix]['weight']) + 1) / 2., 2), 3)

    return solution_with_proba


def to_probability_for_bias_measure(cipher, solution):
    solution_with_proba = deepcopy(solution)
    solution_with_proba['measure'] = 'probability'
    solution_with_proba['total_weight'] = \
        round(-math.log(2 ** (-solution_with_proba['total_weight']) + 1 / 2., 2), 3)
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_proba['components_values'][component.id + suffix]['weight']:
                solution_with_proba['components_values'][component.id + suffix]['weight'] = \
                    round(-math.log(2 ** (-solution_with_proba['components_values'][
                        component.id + suffix]['weight']) + 1 / 2., 2), 3)

    return solution_with_proba


def to_correlation_for_xor_linear_trail(cipher, solution):
    """
    Return the trail of ``solution`` but with the weights corresponding to the correlation.

    The value returned is a solutions in standard format.

    INPUT:

    - ``solution`` -- **dictionary**; a trail found with :py:meth:`~find_lowest_weight_xor_linear_trail`

    EXAMPLES::

        sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, to_correlation_for_xor_linear_trail
        sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4).remove_key_schedule()
        sage: milp = MilpXorLinearModel(speck)
        sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not equal',
        ....: bit_positions=range(32), bit_values=integer_to_bit_list(0x0, 32, 'big'))
        sage: trail = milp.find_lowest_weight_xor_linear_trail([plaintext])
        sage: to_correlation_for_xor_linear_trail(speck, trail) # random
        {'building_time_seconds': 0.10187196731567383,
         'cipher_id': 'speck_p32_k64_o32_r4',
         ...
         'measure': 'correlation',
         ...
         'total_weight': 3.0}
    """
    if solution.get('measure') is None:
        solution_with_correlation = deepcopy(solution)
        solution_with_correlation['measure'] = 'correlation'
        return solution_with_correlation

    if solution.get('measure') == 'bias':
        return to_correlation_for_bias_measure(cipher, solution)

    if solution.get('measure') == 'probability':
        return to_correlation_for_probability_measure(cipher, solution)

    return deepcopy(solution)


def to_correlation_for_bias_measure(cipher, solution):
    solution_with_correlation = deepcopy(solution)
    solution_with_correlation['measure'] = 'correlation'
    solution_with_correlation['total_weight'] -= 1
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_correlation['components_values'][component.id + suffix]['weight']:
                solution_with_correlation['components_values'][component.id + suffix]['weight'] -= 1

    return solution_with_correlation


def to_correlation_for_probability_measure(cipher, solution):
    solution_with_correlation = deepcopy(solution)
    solution_with_correlation['measure'] = 'correlation'
    solution_with_correlation['total_weight'] = \
        round(-math.log(2 * 2 ** (-solution_with_correlation['total_weight']) - 1, 2), 1)
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_correlation['components_values'][component.id + suffix]['weight']:
                solution_with_correlation['components_values'][component.id + suffix]['weight'] = \
                    round(-math.log(2 * 2 ** (-solution_with_correlation['components_values'][
                        component.id + suffix]['weight']) - 1, 2), 1)

    return solution_with_correlation


def find_sign_for_one_xor_linear_trail(cipher, solution):
    """
    Return the trail together with the sign of the weight and of every single component.

    INPUT:

    - ``solution`` -- **dictionary**; the dictionary showing a linear trail for the cipher

    EXAMPLES::

        sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, find_sign_for_one_xor_linear_trail
        sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3).remove_key_schedule()
        sage: milp = MilpXorLinearModel(speck)
        sage: fixed_variables = [set_fixed_variables('plaintext', 'not equal', list(range(32)),
        ....: integer_to_bit_list(0, 32, 'little'))]
        sage: trail = milp.find_lowest_weight_xor_linear_trail(fixed_variables)
        sage: trail_with_sign = find_sign_for_one_xor_linear_trail(speck, trail)
        sage: abs(trail_with_sign['final_sign'])
        1
    """
    constants = {}
    sign = +1
    for component in cipher.get_all_components():
        output_id_link = component.id
        if 'sbox' in component.type:
            input_int = int(solution['components_values'][f'{output_id_link}_i']['value'], 16)
            output_int = int(solution['components_values'][f'{output_id_link}_o']['value'], 16)
            sbox_sign_lat = component.generate_sbox_sign_lat()
            component_sign = sbox_sign_lat[input_int][output_int]
            sign = sign * component_sign
            solution['components_values'][f'{output_id_link}_o']['sign'] = component_sign
        elif 'constant' in component.type:
            output_id_link = component.id
            constants[output_id_link] = component.description
        elif 'word_operation' in component.type:
            if component.description[0] == 'XOR':
                sign = component.get_word_operation_sign(constants, sign, solution)
            else:
                sign = component.get_word_operation_sign(sign, solution)
    solution['final_sign'] = sign

    return solution


def find_sign_for_xor_linear_trails(cipher, solutions):
    """
    Return the trails together with the sign of the weight and of every single component.

    INPUT:

    - ``solutions`` -- **dictionary**; the list of dictionaries showing a linear trail for the cipher.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, find_sign_for_xor_linear_trails
        sage: speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=3).remove_key_schedule()
        sage: milp = MilpXorLinearModel(speck)
        sage: plaintext = set_fixed_variables(
        ....: component_id='plaintext', constraint_type='not equal',
        ....: bit_positions=range(8), bit_values=integer_to_bit_list(0x0, 8, 'big'))
        sage: trails = milp.find_all_xor_linear_trails_with_fixed_weight(1, fixed_values = [plaintext])
        sage: trails_with_sign = find_sign_for_xor_linear_trails(speck, trails)
        sage: abs(trails_with_sign[0]['final_sign'])
        1
    """
    final_solutions = []
    for solution in solutions:
        solution_with_sign = find_sign_for_one_xor_linear_trail(cipher, solution)
        final_solutions.append(solution_with_sign)

    return final_solutions


def get_bit_bindings(cipher, format_func=(lambda x: x)):
    """
    Return two dictionaries.

    A key is an output bit of a component. A value is a list of input bits
    which are the end point of an arc in cipher for the relative key.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import get_bit_bindings
        sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
        sage: speck_without_key_schedule = speck.remove_key_schedule()
        sage: arcs, intermediate_output_arcs = get_bit_bindings(speck_without_key_schedule, '_'.join)
        sage: arcs
        {'key_0_2_0_o': ['xor_0_2_16_i'],
         'key_0_2_10_o': ['xor_0_2_26_i'],
         'key_0_2_11_o': ['xor_0_2_27_i'],
         ...
         'xor_1_8_7_o': ['xor_1_10_7_i', 'cipher_output_1_12_7_i'],
         'xor_1_8_8_o': ['xor_1_10_8_i', 'cipher_output_1_12_8_i'],
         'xor_1_8_9_o': ['xor_1_10_9_i', 'cipher_output_1_12_9_i']}
        sage: intermediate_output_arcs
        {'intermediate_output_0_6': {'intermediate_output_0_6_0_i': ['xor_0_2_0_o',
           'xor_0_4_0_i'],
          'intermediate_output_0_6_10_i': ['xor_0_2_10_o', 'xor_0_4_10_i'],
          'intermediate_output_0_6_11_i': ['xor_0_2_11_o', 'xor_0_4_11_i'],
          ...
          'intermediate_output_0_6_7_i': ['xor_0_2_7_o', 'xor_0_4_7_i'],
          'intermediate_output_0_6_8_i': ['xor_0_2_8_o', 'xor_0_4_8_i'],
          'intermediate_output_0_6_9_i': ['xor_0_2_9_o', 'xor_0_4_9_i']}}
    """
    arcs = {}
    intermediate_output_arcs = {component.id: {} for component in cipher.get_all_components()
                                if INTERMEDIATE_OUTPUT in component.type}
    for component in cipher.get_all_components():
        if component.type == CONSTANT:
            continue
        input_bit_size = component.input_bit_size
        input_id_links = component.input_id_links
        input_bit_positions = component.input_bit_positions
        previous_output_bit_ids = get_previous_output_bit_ids(input_bit_positions, input_id_links, format_func)
        curr_input_bit_ids = [format_func((component.id, f'{i}', 'i')) for i in range(input_bit_size)]
        add_arcs(arcs, component, curr_input_bit_ids, input_bit_size, intermediate_output_arcs, previous_output_bit_ids)

    return arcs, intermediate_output_arcs


def get_single_key_scenario_format_for_fixed_values(_cipher):
    """
    Return a list of dictionary in standard format representing the fixed values in a single key scenario.

    .. SEEALSO::

        :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
        sage: speck = SpeckBlockCipher(number_of_rounds=4)
        sage: fixed_values = get_single_key_scenario_format_for_fixed_values(speck)
        sage: fixed_values[0]["constraint_type"]
        'equal'
        sage: fixed_values[1]["constraint_type"]
        'not_equal'
    """
    fixed_variables = []
    if INPUT_KEY in _cipher.inputs:
        input_size = _cipher.inputs_bit_size[_cipher.inputs.index(INPUT_KEY)]
        list_of_0s = [0] * input_size
        fixed_variable = set_fixed_variables(INPUT_KEY, "equal", list(range(input_size)), list_of_0s)
        fixed_variables.append(fixed_variable)
    possible_inputs = {INPUT_PLAINTEXT, INPUT_MESSAGE, INPUT_STATE}
    for input in set(_cipher.inputs).intersection(possible_inputs):
        input_size = _cipher.inputs_bit_size[_cipher.inputs.index(input)]
        list_of_0s = [0] * input_size
        fixed_variable = set_fixed_variables(input, "not_equal", list(range(input_size)), list_of_0s)
        fixed_variables.append(fixed_variable)

    return fixed_variables


def get_related_key_scenario_format_for_fixed_values(_cipher):
    """
    Return a list of dictionary in standard format representing the fixed values in a related key scenario.

    .. SEEALSO::

        :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.utils import get_related_key_scenario_format_for_fixed_values
        sage: speck = SpeckBlockCipher(number_of_rounds=4)
        sage: fixed_values = get_related_key_scenario_format_for_fixed_values(speck)
        sage: fixed_values[0]["constraint_type"]
        'not_equal'
    """
    fixed_variables = []
    for input_index, input_name in enumerate(_cipher.inputs):
        if input_name == "key":
            input_size = _cipher.inputs_bit_size[input_index]
            list_bits_to_avoid = [0] * input_size
            fixed_variable = set_fixed_variables(input, "not_equal", list(range(input_size)), list_bits_to_avoid)
            fixed_variables.append(fixed_variable)

    return fixed_variables


def _extract_bits(columns, positions):
    """Extracts bits from columns at specified positions using vectorization."""
    bit_size = columns.shape[0] * 8
    positions = np.array(positions)
    byte_indices = (bit_size - positions - 1) // 8
    bit_indices = positions % 8
    if np.any(byte_indices < 0) or np.any(byte_indices >= columns.shape[0]):
        raise IndexError("Byte index out of range.")
    bytes_at_positions = columns[byte_indices][:, :]
    bits = (bytes_at_positions >> bit_indices[:, np.newaxis]) & 1

    return bits


def _number_to_n_bit_binary_string(number, n_bits):
    """Converts a number to an n-bit binary string with leading zero padding."""
    return format(number, f'0{n_bits}b')


def _extract_bit_positions(hex_number, state_size):
    binary_str = _number_to_n_bit_binary_string(hex_number, state_size)
    binary_str = binary_str[::-1]
    positions = [i for i, bit in enumerate(binary_str) if bit == '1']
    return positions


def extract_bits(columns, positions):
    """Extracts the bits from columns at the specified positions."""
    num_positions = len(positions)
    num_columns = columns.shape[1]
    bit_size = columns.shape[0] * 8

    result = np.zeros((num_positions, num_columns), dtype=np.uint8)

    for i in range(num_positions):
        for j in range(num_columns):
            byte_index = (bit_size - positions[i] - 1) // 8
            bit_index = positions[i] % 8
            result[i, j] = get_k_th_bit(columns[:, j][byte_index], bit_index)
    return result


def extract_bit_positions(binary_str):
    """Extracts bit positions from a binary+unknows string."""
    binary_str = binary_str[::-1]
    positions = [i for i, bit in enumerate(binary_str) if bit in ['1', '0']]
    return positions


def _repeat_input_difference(input_difference, num_samples, num_bytes):
    """Function to repeat the input difference for a large sample size."""
    bytes_array = np.frombuffer(input_difference.to_bytes(num_bytes, 'big'), dtype=np.uint8)
    repeated_array = np.broadcast_to(bytes_array[:, np.newaxis], (num_bytes, num_samples))
    return repeated_array


def differential_linear_checker_for_permutation(
        cipher, input_difference, output_mask, number_of_samples, state_size, seed=None
):
    """
    This method helps to verify experimentally differential-linear distinguishers for permutations using the vectorized evaluator
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)

    if seed:
        rng = np.random.default_rng(seed)
    else:
        rng = np.random.default_rng(seed)
    input_difference_data = _repeat_input_difference(input_difference, number_of_samples, num_bytes)
    plaintext1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data
    ciphertext1 = cipher.evaluate_vectorized([plaintext1])
    ciphertext2 = cipher.evaluate_vectorized([plaintext2])
    ciphertext3 = ciphertext1[0] ^ ciphertext2[0]
    bit_positions_ciphertext = _extract_bit_positions(output_mask, state_size)
    ccc = _extract_bits(ciphertext3.T, bit_positions_ciphertext)
    parities = np.bitwise_xor.reduce(ccc, axis=0)
    count = np.count_nonzero(parities == 0)
    corr = 2 * count / number_of_samples * 1.0 - 1
    return corr


def differential_linear_checker_for_block_cipher_single_key(
        cipher, input_difference, output_mask, number_of_samples, block_size, key_size, fixed_key, seed=None
):
    """
    Verifies experimentally differential-linear distinguishers for block ciphers using the vectorized evaluator
    """
    if block_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    if key_size % 8 != 0:
        raise ValueError("Key size must be a multiple of 8.")
    state_num_bytes = int(block_size / 8)
    key_num_bytes = int(key_size / 8)

    if seed:
        rng = np.random.default_rng(seed)
    else:
        rng = np.random.default_rng(seed)
    fixed_key_data = _repeat_input_difference(fixed_key, number_of_samples, key_num_bytes)
    input_difference_data = _repeat_input_difference(input_difference, number_of_samples, state_num_bytes)
    plaintext1 = rng.integers(low=0, high=256, size=(state_num_bytes, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data
    ciphertext1 = cipher.evaluate_vectorized([plaintext1, fixed_key_data])
    ciphertext2 = cipher.evaluate_vectorized([plaintext2, fixed_key_data])
    ciphertext3 = ciphertext1[0] ^ ciphertext2[0]
    bit_positions_ciphertext = _extract_bit_positions(output_mask, block_size)
    ccc = _extract_bits(ciphertext3.T, bit_positions_ciphertext)
    parities = np.bitwise_xor.reduce(ccc, axis=0)
    count = np.count_nonzero(parities == 0)
    corr = 2 * count / number_of_samples * 1.0 - 1
    return corr


def differential_checker_for_permutation(
        cipher, input_difference, output_difference, number_of_samples, state_size, seed=None
):
    """
    Verifies experimentally differential distinguishers for permutations using the vectorized evaluator
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)

    if seed:
        rng = np.random.default_rng(seed)
    else:
        rng = np.random.default_rng(seed)
    input_difference_data = _repeat_input_difference(input_difference, number_of_samples, num_bytes)
    output_difference_data = _repeat_input_difference(output_difference, number_of_samples, num_bytes)
    plaintext1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data

    ciphertext1 = cipher.evaluate_vectorized([plaintext1])
    ciphertext2 = cipher.evaluate_vectorized([plaintext2])
    rows_all_true = np.all((ciphertext1[0] ^ ciphertext2[0] == output_difference_data.T), axis=1)
    total = np.count_nonzero(rows_all_true)
    import math
    total_prob_weight = math.log(total / number_of_samples, 2)
    return total_prob_weight


def differential_truncated_checker_permutation(
        cipher, input_difference, output_difference, number_of_samples, state_size, seed=None
):
    """
    Verifies experimentally differential-truncated distinguishers for permutations in the single-key scenario
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)
    if seed:
        rng = np.random.default_rng(seed)
    else:
        rng = np.random.default_rng(seed)

    input_diff_data = _repeat_input_difference(input_difference, number_of_samples, num_bytes)
    plaintext_data1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext_data2 = plaintext_data1 ^ input_diff_data

    ciphertext1 = cipher.evaluate_vectorized([plaintext_data1])
    ciphertext2 = cipher.evaluate_vectorized([plaintext_data2])
    diff_ciphertext = ciphertext1[0] ^ ciphertext2[0]

    bit_positions = extract_bit_positions(output_difference)
    known_bits = extract_bits(diff_ciphertext.T, bit_positions)
    np.set_printoptions(linewidth=400)

    inv_output_diff = output_difference[::-1]
    filled_bits = [int(bit) for bit in inv_output_diff if bit in ["0", "1"]]
    total = 0
    for i in range(len(known_bits[0])):
        if np.all(known_bits[:, i] == filled_bits):
            total += 1

    prob_weight = math.log(total / number_of_samples, 2)
    return prob_weight


def differential_truncated_checker_single_key(
        cipher, input_difference, output_difference, number_of_samples, state_size, fixed_key, key_size, seed=None
):
    """
    Verifies experimentally differential-truncated distinguishers for block_ciphers in the single-key scenario
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)
    if seed:
        rng = np.random.default_rng(seed)
    else:
        rng = np.random.default_rng(seed)

    key_num_bytes = int(key_size / 8)
    fixed_key_data = _repeat_input_difference(fixed_key, number_of_samples, key_num_bytes)
    input_diff_data = _repeat_input_difference(input_difference, number_of_samples, num_bytes)
    plaintext_data1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext_data2 = plaintext_data1 ^ input_diff_data

    ciphertext1 = cipher.evaluate_vectorized([plaintext_data1, fixed_key_data])
    ciphertext2 = cipher.evaluate_vectorized([plaintext_data2, fixed_key_data])
    diff_ciphertext = ciphertext1[0] ^ ciphertext2[0]
    bit_positions = extract_bit_positions(output_difference)
    known_bits = extract_bits(diff_ciphertext.T, bit_positions)

    inv_output_diff = output_difference[::-1]
    filled_bits = [int(bit) for bit in inv_output_diff if bit in ["0", "1"]]

    total = 0
    for i in range(len(known_bits[0])):
        if np.all(known_bits[:, i] == filled_bits):
            total += 1

    prob_weight = math.log(total / number_of_samples, 2)
    return prob_weight
