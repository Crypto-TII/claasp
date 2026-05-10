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

import re
import json
import math
import os
from concurrent.futures import ProcessPoolExecutor
from copy import deepcopy

import numpy as np

from claasp.name_mappings import (
    CONSTANT,
    CIPHER_OUTPUT,
    INTERMEDIATE_OUTPUT,
    WORD_OPERATION,
    LINEAR_LAYER,
    SBOX,
    MIX_COLUMN,
    INPUT_KEY,
    INPUT_PLAINTEXT,
    INPUT_MESSAGE,
    INPUT_STATE,
)

def hex_to_bitlist(hex_str):
    if not hex_str.startswith(("0x", "0X")):
        raise ValueError("Hex string must start with 0x")
    val_int = int(hex_str, 16)
    bit_len = (len(hex_str) - 2) * 4
    return integer_to_bit_list(val_int, bit_len, "big")

def add_arcs(arcs, component, curr_input_bit_ids, input_bit_size, intermediate_output_arcs, previous_output_bit_ids):
    for i in range(input_bit_size):
        if component.type == INTERMEDIATE_OUTPUT:
            arcs_to_add = arcs[previous_output_bit_ids[i]] if previous_output_bit_ids[i] in arcs else []
            intermediate_output_arcs[component.id][curr_input_bit_ids[i]] = [previous_output_bit_ids[i]] + arcs_to_add
        else:
            if previous_output_bit_ids[i] not in arcs:
                arcs[previous_output_bit_ids[i]] = []
            arcs[previous_output_bit_ids[i]].append(curr_input_bit_ids[i])


def check_if_implemented_component(component):
    component_types = (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN, WORD_OPERATION)
    operation = component.description[0]
    operation_types = ("AND", "OR", "MODADD", "MODSUB", "NOT", "ROTATE", "SHIFT", "XOR")
    if component.type not in component_types or (component.type == WORD_OPERATION and operation not in operation_types):
        print(f"{component.id} not yet implemented")
        return False
    return True


def convert_solver_solution_to_dictionary(
    cipher, model_type, solver_name, solve_time, memory, components_values, total_weight
):
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
        "cipher": cipher,
        "model_type": model_type,
        "solver_name": solver_name,
        "solving_time_seconds": solve_time,
        "memory_megabytes": memory,
        "components_values": components_values,
        "total_weight": total_weight,
    }


def get_previous_output_bit_ids(input_bit_positions, input_id_links, format_func):
    previous_output_bit_ids = []
    for id_link, bit_positions in zip(input_id_links, input_bit_positions):
        previous_output_bit_ids.extend([format_func((id_link, f"{position}", "o")) for position in bit_positions])

    return previous_output_bit_ids


def integer_to_bit_list(int_value, list_length, endianness="little"):
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
    if endianness == "big":
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
        value = solution["components_values"][component_id]["value"]
        weight = str(solution["components_values"][component_id]["weight"])
        weight_cell = f"{'-': <6}"
        if weight != "0":
            weight_cell = f"{weight: <{7 - len(weight)}}"
        line = f"│ {component_id: <25} │ {value: <40} │ {weight_cell} │"
        return line

    horizontal_separator = f"├{'─' * 27}┼{'─' * 42}┼{'─' * 8}┤"
    # ------- header
    print(f"┌{'─' * 27}┬{'─' * 42}┬{'─' * 8}┐")
    print(f"│ {'COMPONENT ID': <26}│ {'VALUE': <41}│ {'WEIGHT'} │")
    print(horizontal_separator)
    # ------- body
    component_ids = list(solution["components_values"].keys())
    for component_id in component_ids[:-1]:
        print(line_formatter(component_id))
        print(horizontal_separator)
    last_component_id = component_ids[-1]
    print(line_formatter(last_component_id))
    print(f"└{'─' * 27}┴{'─' * 42}┴{'─' * 8}┘")


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
    return {"value": value, "weight": weight, "sign": sign}


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
    component_solution = {"value": value}
    if weight is not None:
        component_solution["weight"] = weight
    if sign is not None:
        component_solution["sign"] = sign
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
        "component_id": component_id,
        "constraint_type": constraint_type,
        "bit_positions": bit_positions,
        "bit_values": bit_values,
    }

def join_and_sanitize_strings(l):
    """
    Join a list of strings using ``_`` and sanitize the resulting string so that it only
    contains alphanumeric characters, ``.``, ``_`` or ``-``. The returned string is
    prefixed with ``_``.

    INPUT:

    - ``l`` -- **list** (or ``None``); list of strings to be joined and sanitized. If ``None``,
      an empty string is returned.

    OUTPUT:

    - **string**; a sanitized string obtained by joining the elements of ``l`` with ``_``,
      removing all characters except ``[a-zA-Z0-9._-]``, and prefixing the result with ``_``.
      If ``l`` is ``None``, the function returns ``""``.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.utils import join_and_sanitize_strings
        sage: join_and_sanitize_strings(['sat', 'xor-linear'])
        '_sat_xor-linear'

        sage: join_and_sanitize_strings(['model°', 'round#1'])
        '_model_round1'

        sage: join_and_sanitize_strings(None)
        ''
    """
    if l is None:
        return ""
    joined = "_".join(l)
    return "_" + re.sub(r"[^a-zA-Z0-9._-]", "", joined)

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
    with open(file_name, "w") as output_file:
        output_file.write("\n".join(model_to_write) + "\n")
        output_file.close()


def write_solution_to_file(solution, file_path):
    """
    Write the solver solution into a file.

    INPUT:

    - ``solution`` -- **dictionary**; the solution in standard format
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
    dirname = os.path.dirname(file_path)
    os.makedirs(dirname, exist_ok=True)
    solution["cipher"] = str(solution["cipher"])
    with open(file_path, "w") as file:
        file.write(json.dumps(solution, indent=4))


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
    if solution.get("measure") in (None, "correlation"):
        return to_bias_for_correlation_measure(cipher, solution)

    if solution.get("measure") == "probability":
        return to_bias_for_probability_measure(cipher, solution)

    return deepcopy(solution)


def to_bias_for_correlation_measure(cipher, solution):
    solution_with_bias = deepcopy(solution)
    solution_with_bias["measure"] = "bias"
    solution_with_bias["total_weight"] += 1
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_bias["components_values"][component.id + suffix]["weight"]:
                solution_with_bias["components_values"][component.id + suffix]["weight"] += 1

    return solution_with_bias


def to_bias_for_probability_measure(cipher, solution):
    solution_with_bias = deepcopy(solution)
    solution_with_bias["measure"] = "bias"
    solution_with_bias["total_weight"] = round(-math.log(2 ** (-solution_with_bias["total_weight"]) - 1 / 2.0, 2), 1)
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_bias["components_values"][component.id + suffix]["weight"]:
                solution_with_bias["components_values"][component.id + suffix]["weight"] = round(
                    -math.log(
                        2 ** (-solution_with_bias["components_values"][component.id + suffix]["weight"]) - 1 / 2.0, 2
                    ),
                    1,
                )

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
    if solution.get("measure") in (None, "correlation"):
        return to_probability_for_correlation_measure(cipher, solution)

    if solution.get("measure") == "bias":
        return to_probability_for_bias_measure(cipher, solution)

    return deepcopy(solution)


def to_probability_for_correlation_measure(cipher, solution):
    solution_with_proba = deepcopy(solution)
    solution_with_proba["measure"] = "probability"
    solution_with_proba["total_weight"] = round(
        -math.log((2 ** (-solution_with_proba["total_weight"]) + 1) / 2.0, 2), 3
    )
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_proba["components_values"][component.id + suffix]["weight"]:
                solution_with_proba["components_values"][component.id + suffix]["weight"] = round(
                    -math.log(
                        (2 ** (-solution_with_proba["components_values"][component.id + suffix]["weight"]) + 1) / 2.0, 2
                    ),
                    3,
                )

    return solution_with_proba


def to_probability_for_bias_measure(cipher, solution):
    solution_with_proba = deepcopy(solution)
    solution_with_proba["measure"] = "probability"
    solution_with_proba["total_weight"] = round(-math.log(2 ** (-solution_with_proba["total_weight"]) + 1 / 2.0, 2), 3)
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_proba["components_values"][component.id + suffix]["weight"]:
                solution_with_proba["components_values"][component.id + suffix]["weight"] = round(
                    -math.log(
                        2 ** (-solution_with_proba["components_values"][component.id + suffix]["weight"]) + 1 / 2.0, 2
                    ),
                    3,
                )

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
    if solution.get("measure") is None:
        solution_with_correlation = deepcopy(solution)
        solution_with_correlation["measure"] = "correlation"
        return solution_with_correlation

    if solution.get("measure") == "bias":
        return to_correlation_for_bias_measure(cipher, solution)

    if solution.get("measure") == "probability":
        return to_correlation_for_probability_measure(cipher, solution)

    return deepcopy(solution)


def to_correlation_for_bias_measure(cipher, solution):
    solution_with_correlation = deepcopy(solution)
    solution_with_correlation["measure"] = "correlation"
    solution_with_correlation["total_weight"] -= 1
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_correlation["components_values"][component.id + suffix]["weight"]:
                solution_with_correlation["components_values"][component.id + suffix]["weight"] -= 1

    return solution_with_correlation


def to_correlation_for_probability_measure(cipher, solution):
    solution_with_correlation = deepcopy(solution)
    solution_with_correlation["measure"] = "correlation"
    solution_with_correlation["total_weight"] = round(
        -math.log(2 * 2 ** (-solution_with_correlation["total_weight"]) - 1, 2), 1
    )
    for component in cipher.get_all_components():
        suffix_list = component.suffixes
        for suffix in suffix_list:
            if solution_with_correlation["components_values"][component.id + suffix]["weight"]:
                solution_with_correlation["components_values"][component.id + suffix]["weight"] = round(
                    -math.log(
                        2 * 2 ** (-solution_with_correlation["components_values"][component.id + suffix]["weight"]) - 1,
                        2,
                    ),
                    1,
                )

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
        if "sbox" in component.type:
            input_int = int(solution["components_values"][f"{output_id_link}_i"]["value"], 16)
            output_int = int(solution["components_values"][f"{output_id_link}_o"]["value"], 16)
            sbox_sign_lat = component.generate_sbox_sign_lat()
            component_sign = sbox_sign_lat[input_int][output_int]
            sign = sign * component_sign
            solution["components_values"][f"{output_id_link}_o"]["sign"] = component_sign
        elif "constant" in component.type:
            output_id_link = component.id
            constants[output_id_link] = component.description
        elif "word_operation" in component.type:
            if component.description[0] == "XOR":
                sign = component.get_word_operation_sign(constants, sign, solution)
            else:
                sign = component.get_word_operation_sign(sign, solution)
    solution["final_sign"] = sign

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
    intermediate_output_arcs = {
        component.id: {} for component in cipher.get_all_components() if INTERMEDIATE_OUTPUT in component.type
    }
    for component in cipher.get_all_components():
        if component.type == CONSTANT:
            continue
        input_bit_size = component.input_bit_size
        input_id_links = component.input_id_links
        input_bit_positions = component.input_bit_positions
        previous_output_bit_ids = get_previous_output_bit_ids(input_bit_positions, input_id_links, format_func)
        curr_input_bit_ids = [format_func((component.id, f"{i}", "i")) for i in range(input_bit_size)]
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
    for cipher_input in set(_cipher.inputs).intersection(possible_inputs):
        input_size = _cipher.inputs_bit_size[_cipher.inputs.index(cipher_input)]
        list_of_0s = [0] * input_size
        fixed_variable = set_fixed_variables(cipher_input, "not_equal", list(range(input_size)), list_of_0s)
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
        if input_name == INPUT_KEY:
            input_size = _cipher.inputs_bit_size[input_index]
            list_bits_to_avoid = [0] * input_size
            fixed_variable = set_fixed_variables(input, "not_equal", list(range(input_size)), list_bits_to_avoid)
            fixed_variables.append(fixed_variable)

    return fixed_variables


def _number_to_n_bit_binary_string(number, n_bits):
    """Converts a number to an n-bit binary string with leading zero padding."""
    return format(number, f"0{n_bits}b")


def _extract_bit_positions_msb(binary_str, bits_to_consider=("0", "1")):
    """Return positions (MSB first) of all determined bits in a pattern string."""
    return [index for index, bit in enumerate(binary_str) if bit in bits_to_consider]


def _extract_bits_msb(columns, positions):
    """Extract bits assuming position 0 corresponds to the MSB of byte 0."""
    positions = np.array(positions)
    byte_indices = positions // 8
    bit_indices = 7 - (positions % 8)
    if np.any(byte_indices < 0) or np.any(byte_indices >= columns.shape[0]):
        raise IndexError("Byte index out of range.")
    bytes_at_positions = columns[byte_indices][:, :]
    return (bytes_at_positions >> bit_indices[:, np.newaxis]) & 1


def _repeat_input_difference_msb(input_difference, num_samples, num_bytes):
    """Repeat an input difference keeping bit position 0 at the MSB."""
    return _repeat_input_difference(input_difference, num_samples, num_bytes)


def _repeat_input_difference(input_difference, num_samples, num_bytes):
    """Function to repeat the input difference for a large sample size."""
    bytes_array = np.frombuffer(input_difference.to_bytes(num_bytes, "big"), dtype=np.uint8)
    repeated_array = np.broadcast_to(bytes_array[:, np.newaxis], (num_bytes, num_samples))
    return repeated_array


# ---------------------------------------------------------------------------
# Module-level worker functions (must be picklable for ProcessPoolExecutor)
# Each returns the "count" statistic for its chunk; the caller aggregates.
# ---------------------------------------------------------------------------

def _w_diff_linear_sk(args):
    cipher, input_difference, output_mask, state_num_bytes, key_num_bytes, fixed_key, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    fk = _repeat_input_difference(fixed_key, chunk_size, key_num_bytes)
    id_ = _repeat_input_difference(input_difference, chunk_size, state_num_bytes)
    p1 = rng.integers(0, 256, size=(state_num_bytes, chunk_size), dtype=np.uint8)
    p2 = p1 ^ id_
    c1 = cipher.evaluate_vectorized([p1, fk])
    c2 = cipher.evaluate_vectorized([p2, fk])
    c3 = c1[0] ^ c2[0]
    bit_pos = _extract_bit_positions_msb(output_mask, ("1",))
    ccc = _extract_bits_msb(c3.T, bit_pos)
    parities = np.bitwise_xor.reduce(ccc, axis=0)
    return int(np.count_nonzero(parities == 0))


def _w_linear_sk(args):
    cipher, input_mask, output_mask, state_num_bytes, key_num_bytes, fixed_key, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    fk = _repeat_input_difference(fixed_key, chunk_size, key_num_bytes)
    plaintext = rng.integers(0, 256, size=(state_num_bytes, chunk_size), dtype=np.uint8)
    ciphertext = cipher.evaluate_vectorized([plaintext, fk])[0]
    in_pos = _extract_bit_positions_msb(input_mask, ("1",))
    out_pos = _extract_bit_positions_msb(output_mask, ("1",))
    in_par = np.bitwise_xor.reduce(_extract_bits_msb(plaintext, in_pos), axis=0) if len(in_pos) > 0 else np.zeros(chunk_size, dtype=np.uint8)
    out_par = np.bitwise_xor.reduce(_extract_bits_msb(ciphertext.T, out_pos), axis=0) if len(out_pos) > 0 else np.zeros(chunk_size, dtype=np.uint8)
    return int(np.count_nonzero((in_par ^ out_par) == 0))


def _w_diff_perm(args):
    cipher, input_difference, output_difference, num_bytes, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    id_ = _repeat_input_difference(input_difference, chunk_size, num_bytes)
    od_ = _repeat_input_difference(output_difference, chunk_size, num_bytes)
    p1 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    p2 = p1 ^ id_
    c1 = cipher.evaluate_vectorized([p1])
    c2 = cipher.evaluate_vectorized([p2])
    return int(np.count_nonzero(np.all(c1[0] ^ c2[0] == od_.T, axis=1)))


def _w_diff_trunc_perm(args):
    cipher, input_difference, output_difference, num_bytes, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    id_ = _repeat_input_difference_msb(input_difference, chunk_size, num_bytes)
    p1 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    p2 = p1 ^ id_
    c1 = cipher.evaluate_vectorized([p1])
    c2 = cipher.evaluate_vectorized([p2])
    diff = c1[0] ^ c2[0]
    bit_pos = _extract_bit_positions_msb(output_difference)
    known = _extract_bits_msb(diff.T, bit_pos)
    filled = np.array([int(output_difference[p]) for p in bit_pos], dtype=np.uint8)[:, np.newaxis]
    return int(np.all(known == filled, axis=0).sum())


def _w_diff_trunc_sk(args):
    cipher, input_difference, output_difference, num_bytes, key_num_bytes, fixed_key, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    fk = _repeat_input_difference(fixed_key, chunk_size, key_num_bytes)
    id_ = _repeat_input_difference(input_difference, chunk_size, num_bytes)
    p1 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    p2 = p1 ^ id_
    c1 = cipher.evaluate_vectorized([p1, fk])
    c2 = cipher.evaluate_vectorized([p2, fk])
    diff = c1[0] ^ c2[0]
    bit_pos = _extract_bit_positions_msb(output_difference)
    known = _extract_bits_msb(diff.T, bit_pos)
    filled = np.array([int(b) for b in output_difference if b in ("0", "1")], dtype=np.uint8)[:, np.newaxis]
    return int(np.all(known == filled, axis=0).sum())


def _w_sdpi_diff_perm(args):
    cipher, input_difference, output_difference, num_bytes, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    id_ = _repeat_input_difference(input_difference, chunk_size, num_bytes)
    od_ = _repeat_input_difference(output_difference, chunk_size, num_bytes)
    p1 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    p2 = p1 ^ id_
    p11 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    p22 = p11 ^ id_
    c1 = cipher.evaluate_vectorized([p1])
    c2 = cipher.evaluate_vectorized([p2])
    c11 = cipher.evaluate_vectorized([p11])
    c22 = cipher.evaluate_vectorized([p22])
    return int(np.count_nonzero(np.all(c1[0] ^ c2[0] ^ c11[0] ^ c22[0] == od_.T, axis=1)))


def _w_sdpi_diff_linear_perm(args):
    cipher, input_difference, output_mask, num_bytes, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    id_ = _repeat_input_difference(input_difference, chunk_size, num_bytes)
    bcf1 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    bcf2 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    p1 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    p2 = p1 ^ id_
    p11 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    p22 = p11 ^ id_
    c1 = cipher.evaluate_vectorized([bcf1, p1])
    c2 = cipher.evaluate_vectorized([bcf1, p2])
    c11 = cipher.evaluate_vectorized([bcf2, p11])
    c22 = cipher.evaluate_vectorized([bcf2, p22])
    c3 = c1[0] ^ c2[0] ^ c11[0] ^ c22[0]
    bit_pos = _extract_bit_positions_msb(output_mask, ("1",))
    ccc = _extract_bits_msb(c3.T, bit_pos)
    parities = np.bitwise_xor.reduce(ccc, axis=0)
    return int(np.count_nonzero(parities == 0))


def _w_diff_trunc_perm_io(args):
    cipher, input_trunc_diff, output_trunc_diff, state_size, num_bytes, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    p1 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    mask = _sample_truncated_difference_from_string(input_trunc_diff, chunk_size, state_size, rng)
    p2 = p1 ^ mask
    c1 = cipher.evaluate_vectorized([p1])[0]
    c2 = cipher.evaluate_vectorized([p2])[0]
    diff = c1 ^ c2
    bit_pos = _extract_bit_positions_msb(output_trunc_diff)
    if not bit_pos:
        return chunk_size
    known = _extract_bits_msb(diff.T, bit_pos)
    filled = np.array([int(output_trunc_diff[p]) for p in bit_pos], dtype=np.uint8)[:, None]
    return int(np.all(known == filled, axis=0).sum())


def _w_trunc_diff_linear_perm(args):
    cipher, input_trunc_diff, output_mask, state_size, num_bytes, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    p1 = rng.integers(0, 256, size=(num_bytes, chunk_size), dtype=np.uint8)
    mask = _sample_truncated_difference_from_string(input_trunc_diff, chunk_size, state_size, rng)
    p2 = p1 ^ mask
    c1 = cipher.evaluate_vectorized([p1])
    c2 = cipher.evaluate_vectorized([p2])
    c3 = c1[0] ^ c2[0]
    bit_pos = _extract_bit_positions_msb(output_mask, ("1",))
    ccc = _extract_bits_msb(c3.T, bit_pos)
    parities = np.bitwise_xor.reduce(ccc, axis=0)
    return int(np.count_nonzero(parities == 0))


def _get_data_for_cipher_inputs(cipher, data_by_input_id):
    return [data_by_input_id[input_id] for input_id in cipher.inputs]


def _get_state_input_id(cipher, preferred_input_id=None):
    if preferred_input_id is not None:
        return preferred_input_id

    possible_inputs = (INPUT_PLAINTEXT, INPUT_MESSAGE, INPUT_STATE)
    for input_id in cipher.inputs:
        if input_id in possible_inputs:
            return input_id

    return cipher.inputs[0]


def _get_fixed_input_value(fixed_inputs, input_id, default_value=None):
    if fixed_inputs is None:
        return default_value
    if isinstance(fixed_inputs, dict):
        return fixed_inputs.get(input_id, default_value)
    return fixed_inputs


def _get_auxiliary_input_data(cipher, state_input_id, number_of_samples, rng, fixed_inputs=None):
    auxiliary_input_data = {}
    for input_id, input_bit_size in zip(cipher.inputs, cipher.inputs_bit_size):
        if input_id == state_input_id:
            continue
        if input_bit_size % 8 != 0:
            raise ValueError("Input sizes must be multiples of 8.")
        input_num_bytes = input_bit_size // 8
        fixed_value = _get_fixed_input_value(fixed_inputs, input_id)
        if fixed_value is None:
            auxiliary_input_data[input_id] = rng.integers(
                low=0, high=256, size=(input_num_bytes, number_of_samples), dtype=np.uint8
            )
        else:
            auxiliary_input_data[input_id] = _repeat_input_difference(fixed_value, number_of_samples, input_num_bytes)

    return auxiliary_input_data


def _count_boomerang_matches(cipher, input_difference, output_difference, number_of_samples, state_size, rng,
                             auxiliary_input_data=None, state_input_id=None):
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")

    state_num_bytes = state_size // 8
    state_input_id = _get_state_input_id(cipher, state_input_id)
    auxiliary_input_data = {} if auxiliary_input_data is None else auxiliary_input_data
    input_difference_data = _repeat_input_difference(input_difference, number_of_samples, state_num_bytes)
    output_difference_data = _repeat_input_difference(output_difference, number_of_samples, state_num_bytes)

    plaintext_data_0 = rng.integers(low=0, high=256, size=(state_num_bytes, number_of_samples), dtype=np.uint8)
    plaintext_data_1 = plaintext_data_0 ^ input_difference_data

    input_data_0 = {state_input_id: plaintext_data_0, **auxiliary_input_data}
    input_data_1 = {state_input_id: plaintext_data_1, **auxiliary_input_data}
    ciphertext_data_0 = cipher.evaluate_vectorized(_get_data_for_cipher_inputs(cipher, input_data_0))[0]
    ciphertext_data_1 = cipher.evaluate_vectorized(_get_data_for_cipher_inputs(cipher, input_data_1))[0]

    inverse_cipher = cipher.cipher_inverse()
    inverse_state_input_id = _get_state_input_id(inverse_cipher)
    inverse_auxiliary_input_data = {
        input_id: auxiliary_input_data[input_id]
        for input_id in inverse_cipher.inputs
        if input_id != inverse_state_input_id and input_id in auxiliary_input_data
    }
    missing_input_ids = [
        input_id
        for input_id in inverse_cipher.inputs
        if input_id != inverse_state_input_id and input_id not in inverse_auxiliary_input_data
    ]
    if missing_input_ids:
        raise ValueError(f"Missing auxiliary input data for inverse cipher inputs: {missing_input_ids}.")

    output_xor_difference_0 = (ciphertext_data_0 ^ output_difference_data.T).T
    output_xor_difference_1 = (ciphertext_data_1 ^ output_difference_data.T).T
    inverse_input_data_0 = {inverse_state_input_id: output_xor_difference_0, **inverse_auxiliary_input_data}
    inverse_input_data_1 = {inverse_state_input_id: output_xor_difference_1, **inverse_auxiliary_input_data}
    plaintext_data_2 = inverse_cipher.evaluate_vectorized(
        _get_data_for_cipher_inputs(inverse_cipher, inverse_input_data_0)
    )[0]
    plaintext_data_3 = inverse_cipher.evaluate_vectorized(
        _get_data_for_cipher_inputs(inverse_cipher, inverse_input_data_1)
    )[0]

    return int(np.count_nonzero(np.all(plaintext_data_2 ^ plaintext_data_3 == input_difference_data.T, axis=1)))


def _w_boomerang_perm(args):
    cipher, input_difference, output_difference, state_size, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    return _count_boomerang_matches(cipher, input_difference, output_difference, chunk_size, state_size, rng)


def _w_boomerang_sk(args):
    cipher, input_difference, output_difference, state_size, fixed_inputs, state_input_id, chunk_size, seed = args
    rng = np.random.default_rng(seed)
    state_input_id = _get_state_input_id(cipher, state_input_id)
    auxiliary_input_data = _get_auxiliary_input_data(cipher, state_input_id, chunk_size, rng, fixed_inputs)
    return _count_boomerang_matches(
        cipher, input_difference, output_difference, chunk_size, state_size, rng, auxiliary_input_data, state_input_id
    )


def _parallel_dispatch(worker_func, fixed_args, number_of_samples, num_workers, seed):
    """Split samples into chunks, run worker_func on each in parallel, return (total_count, total_samples)."""
    base_chunk = number_of_samples // num_workers
    remainder = number_of_samples % num_workers
    rng = np.random.default_rng(seed)
    seeds = rng.integers(0, 2 ** 31, size=num_workers).tolist()
    args_list = [
        fixed_args + (base_chunk + (1 if i < remainder else 0), int(s))
        for i, s in enumerate(seeds)
    ]
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        counts = list(executor.map(worker_func, args_list))
    return sum(counts), number_of_samples


def differential_linear_checker_for_block_cipher_single_key(
    cipher, input_difference, output_mask, number_of_samples, block_size, key_size, fixed_key, seed=None,
    num_workers=1
):
    """
    Verify experimentally differential-linear distinguishers for block ciphers using the vectorized evaluator.

    INPUT:

    - ``cipher`` -- **Cipher object**; cipher instance providing ``evaluate_vectorized``
    - ``input_difference`` -- **integer**; input XOR difference
    - ``output_mask`` -- **string**; output linear mask as a bitstring of length ``block_size``
    - ``number_of_samples`` -- **integer**; number of random plaintext pairs
    - ``block_size`` -- **integer**; block size in bits (must be multiple of 8)
    - ``key_size`` -- **integer**; key size in bits (must be multiple of 8)
    - ``fixed_key`` -- **integer**; fixed key value for the single-key scenario
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical correlation in the interval ``[-1, 1]``
    """
    if block_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    if key_size % 8 != 0:
        raise ValueError("Key size must be a multiple of 8.")
    state_num_bytes = int(block_size / 8)
    key_num_bytes = int(key_size / 8)
    if num_workers > 1:
        count, total = _parallel_dispatch(
            _w_diff_linear_sk,
            (cipher, input_difference, output_mask, state_num_bytes, key_num_bytes, fixed_key),
            number_of_samples, num_workers, seed,
        )
        return 2 * count / total - 1.0
    rng = np.random.default_rng(seed)
    fixed_key_data = _repeat_input_difference(fixed_key, number_of_samples, key_num_bytes)
    input_difference_data = _repeat_input_difference(input_difference, number_of_samples, state_num_bytes)
    plaintext1 = rng.integers(low=0, high=256, size=(state_num_bytes, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data
    ciphertext1 = cipher.evaluate_vectorized([plaintext1, fixed_key_data])
    ciphertext2 = cipher.evaluate_vectorized([plaintext2, fixed_key_data])
    ciphertext3 = ciphertext1[0] ^ ciphertext2[0]
    bit_positions_ciphertext = _extract_bit_positions_msb(output_mask, ("1",))
    ccc = _extract_bits_msb(ciphertext3.T, bit_positions_ciphertext)
    parities = np.bitwise_xor.reduce(ccc, axis=0)
    count = np.count_nonzero(parities == 0)
    corr = 2 * count / number_of_samples * 1.0 - 1
    return corr


def linear_checker_for_block_cipher_single_key(
    cipher, input_mask, output_mask, number_of_samples, block_size, key_size, fixed_key, seed=None,
    num_workers=1
):
    """
    Verify experimentally linear distinguishers for block ciphers in a single-key scenario.

    INPUT:

    - ``cipher`` -- **Cipher object**; cipher instance providing ``evaluate_vectorized``
    - ``input_mask`` -- **string**; input linear mask as a bitstring of length ``block_size``
    - ``output_mask`` -- **string**; output linear mask as a bitstring of length ``block_size``
    - ``number_of_samples`` -- **integer**; number of random plaintext samples
    - ``block_size`` -- **integer**; block size in bits (must be multiple of 8)
    - ``key_size`` -- **integer**; key size in bits (must be multiple of 8)
    - ``fixed_key`` -- **integer**; fixed key value for the single-key scenario
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical correlation in the interval ``[-1, 1]``
    """
    if block_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    if key_size % 8 != 0:
        raise ValueError("Key size must be a multiple of 8.")
    if len(input_mask) != block_size:
        raise ValueError("Input mask length must be equal to block_size.")
    if len(output_mask) != block_size:
        raise ValueError("Output mask length must be equal to block_size.")

    state_num_bytes = int(block_size / 8)
    key_num_bytes = int(key_size / 8)

    if num_workers > 1:
        count, total = _parallel_dispatch(
            _w_linear_sk,
            (cipher, input_mask, output_mask, state_num_bytes, key_num_bytes, fixed_key),
            number_of_samples, num_workers, seed,
        )
        return 2 * count / total - 1.0

    rng = np.random.default_rng(seed)
    fixed_key_data = _repeat_input_difference(fixed_key, number_of_samples, key_num_bytes)
    plaintext = rng.integers(low=0, high=256, size=(state_num_bytes, number_of_samples), dtype=np.uint8)
    ciphertext = cipher.evaluate_vectorized([plaintext, fixed_key_data])[0]

    input_positions = _extract_bit_positions_msb(input_mask, ("1",))
    output_positions = _extract_bit_positions_msb(output_mask, ("1",))

    if input_positions:
        input_bits = _extract_bits_msb(plaintext, input_positions)
        input_parity = np.bitwise_xor.reduce(input_bits, axis=0)
    else:
        input_parity = np.zeros(number_of_samples, dtype=np.uint8)

    if output_positions:
        output_bits = _extract_bits_msb(ciphertext.T, output_positions)
        output_parity = np.bitwise_xor.reduce(output_bits, axis=0)
    else:
        output_parity = np.zeros(number_of_samples, dtype=np.uint8)

    total_parity = input_parity ^ output_parity
    count = np.count_nonzero(total_parity == 0)
    corr = 2 * count / number_of_samples * 1.0 - 1
    return corr


def differential_checker_permutation(
    cipher, input_difference, output_difference, number_of_samples, state_size, seed=None, num_workers=1
):
    """
    Verify experimentally differential distinguishers for permutations using the vectorized evaluator.

    INPUT:

    - ``cipher`` -- **Cipher object**; permutation instance providing ``evaluate_vectorized``
    - ``input_difference`` -- **integer**; input XOR difference
    - ``output_difference`` -- **integer**; expected output XOR difference
    - ``number_of_samples`` -- **integer**; number of random plaintext pairs
    - ``state_size`` -- **integer**; permutation state size in bits (must be multiple of 8)
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical probability weight ``log2(matches / number_of_samples)``
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)

    if num_workers > 1:
        total, n = _parallel_dispatch(
            _w_diff_perm,
            (cipher, input_difference, output_difference, num_bytes),
            number_of_samples, num_workers, seed,
        )
        return math.log(total / n, 2)

    rng = np.random.default_rng(seed)
    input_difference_data = _repeat_input_difference(input_difference, number_of_samples, num_bytes)
    output_difference_data = _repeat_input_difference(output_difference, number_of_samples, num_bytes)
    plaintext1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data

    ciphertext1 = cipher.evaluate_vectorized([plaintext1])
    ciphertext2 = cipher.evaluate_vectorized([plaintext2])
    rows_all_true = np.all((ciphertext1[0] ^ ciphertext2[0] == output_difference_data.T), axis=1)
    total = np.count_nonzero(rows_all_true)

    total_prob_weight = math.log(total / number_of_samples, 2)
    return total_prob_weight


def boomerang_distinguisher_checker_permutation(
    cipher, input_difference, output_difference, number_of_samples, state_size, seed=None, num_workers=1
):
    """
    Verify experimentally boomerang distinguishers for permutations using the vectorized evaluator.

    INPUT:

    - ``cipher`` -- **Cipher object**; permutation instance providing ``evaluate_vectorized`` and ``cipher_inverse``
    - ``input_difference`` -- **integer**; input XOR difference
    - ``output_difference`` -- **integer**; output XOR difference
    - ``number_of_samples`` -- **integer**; number of random plaintext pairs
    - ``state_size`` -- **integer**; permutation state size in bits (must be multiple of 8)
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical boomerang probability in the interval ``[0, 1]``
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")

    if num_workers > 1:
        total, n = _parallel_dispatch(
            _w_boomerang_perm,
            (cipher, input_difference, output_difference, state_size),
            number_of_samples, num_workers, seed,
        )
        return total / n

    rng = np.random.default_rng(seed)
    total = _count_boomerang_matches(cipher, input_difference, output_difference, number_of_samples, state_size, rng)
    return total / number_of_samples


def boomerang_distinguisher_checker_for_block_cipher_single_key(
    cipher,
    input_difference,
    output_difference,
    number_of_samples,
    block_size,
    fixed_key=0,
    seed=None,
    num_workers=1,
    state_input_id=None,
):
    """
    Verify experimentally boomerang distinguishers for block ciphers in a single-key scenario.

    INPUT:

    - ``cipher`` -- **Cipher object**; cipher instance providing ``evaluate_vectorized`` and ``cipher_inverse``
    - ``input_difference`` -- **integer**; input XOR difference
    - ``output_difference`` -- **integer**; output XOR difference
    - ``number_of_samples`` -- **integer**; number of random plaintext pairs
    - ``block_size`` -- **integer**; block size in bits (must be multiple of 8)
    - ``fixed_key`` -- **integer or dict** (default: `0`); fixed key value, or a dictionary mapping cipher input ids to
      fixed integer values. If ``None``, non-state inputs are sampled randomly.
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes
    - ``state_input_id`` -- **string** (default: `None`); cipher input id used as the plaintext/state input

    OUTPUT:

    - This method returns a **float**; the empirical boomerang probability in the interval ``[0, 1]``
    """
    if block_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")

    if num_workers > 1:
        total, n = _parallel_dispatch(
            _w_boomerang_sk,
            (cipher, input_difference, output_difference, block_size, fixed_key, state_input_id),
            number_of_samples, num_workers, seed,
        )
        return total / n

    rng = np.random.default_rng(seed)
    state_input_id = _get_state_input_id(cipher, state_input_id)
    auxiliary_input_data = _get_auxiliary_input_data(cipher, state_input_id, number_of_samples, rng, fixed_key)
    total = _count_boomerang_matches(
        cipher, input_difference, output_difference, number_of_samples, block_size, rng, auxiliary_input_data,
        state_input_id
    )
    return total / number_of_samples


def differential_truncated_checker_permutation(
    cipher, input_difference, output_difference, number_of_samples, state_size, seed=None, num_workers=1
):
    """
    Verify experimentally differential-truncated distinguishers for permutations.

    INPUT:

    - ``cipher`` -- **Cipher object**; permutation instance providing ``evaluate_vectorized``
    - ``input_difference`` -- **integer**; input XOR difference
    - ``output_difference`` -- **string**; truncated output pattern over ``{'0','1','?','2'}``
    - ``number_of_samples`` -- **integer**; number of random plaintext pairs
    - ``state_size`` -- **integer**; permutation state size in bits (must be multiple of 8)
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical probability weight, or ``-inf`` if no match is found
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)

    if num_workers > 1:
        total, n = _parallel_dispatch(
            _w_diff_trunc_perm,
            (cipher, input_difference, output_difference, num_bytes),
            number_of_samples, num_workers, seed,
        )
        if total == 0:
            print(f"\nWARNING: No matches found out of {n} samples!")
            return float("-inf")
        return math.log(total / n, 2)

    rng = np.random.default_rng(seed)

    input_diff_data = _repeat_input_difference_msb(input_difference, number_of_samples, num_bytes)
    plaintext_data1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext_data2 = plaintext_data1 ^ input_diff_data

    ciphertext1 = cipher.evaluate_vectorized([plaintext_data1])
    ciphertext2 = cipher.evaluate_vectorized([plaintext_data2])
    diff_ciphertext = ciphertext1[0] ^ ciphertext2[0]

    bit_positions = _extract_bit_positions_msb(output_difference)
    known_bits = _extract_bits_msb(diff_ciphertext.T, bit_positions)
    np.set_printoptions(linewidth=400)

    filled_bits = np.array([int(output_difference[pos]) for pos in bit_positions], dtype=np.uint8)[:, np.newaxis]
    total = int(np.all(known_bits == filled_bits, axis=0).sum())

    if total == 0:
        print(f"\nWARNING: No matches found out of {number_of_samples} samples!")
        return float("-inf")

    prob_weight = math.log(total / number_of_samples, 2)
    return prob_weight


def differential_truncated_checker_single_key(
    cipher, input_difference, output_difference, number_of_samples, state_size, fixed_key, key_size, seed=None,
    num_workers=1
):
    """
    Verify experimentally differential-truncated distinguishers for block ciphers in the single-key scenario.

    INPUT:

    - ``cipher`` -- **Cipher object**; cipher instance providing ``evaluate_vectorized``
    - ``input_difference`` -- **integer**; input XOR difference
    - ``output_difference`` -- **string**; truncated output pattern over ``{'0','1','?','2'}``
    - ``number_of_samples`` -- **integer**; number of random plaintext pairs
    - ``state_size`` -- **integer**; block size in bits (must be multiple of 8)
    - ``fixed_key`` -- **integer**; fixed key value for the single-key scenario
    - ``key_size`` -- **integer**; key size in bits (must be multiple of 8)
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical probability weight ``log2(matches / number_of_samples)``
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)
    key_num_bytes = int(key_size / 8)

    if num_workers > 1:
        total, n = _parallel_dispatch(
            _w_diff_trunc_sk,
            (cipher, input_difference, output_difference, num_bytes, key_num_bytes, fixed_key),
            number_of_samples, num_workers, seed,
        )
        if total == 0:
            return float("-inf")
        return math.log(total / n, 2)

    rng = np.random.default_rng(seed)

    fixed_key_data = _repeat_input_difference(fixed_key, number_of_samples, key_num_bytes)
    input_diff_data = _repeat_input_difference(input_difference, number_of_samples, num_bytes)
    plaintext_data1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext_data2 = plaintext_data1 ^ input_diff_data

    ciphertext1 = cipher.evaluate_vectorized([plaintext_data1, fixed_key_data])
    ciphertext2 = cipher.evaluate_vectorized([plaintext_data2, fixed_key_data])
    diff_ciphertext = ciphertext1[0] ^ ciphertext2[0]
    bit_positions = _extract_bit_positions_msb(output_difference)
    known_bits = _extract_bits_msb(diff_ciphertext.T, bit_positions)

    filled_bits = np.array([int(bit) for bit in output_difference if bit in ("0", "1")], dtype=np.uint8)[:, np.newaxis]
    total = int(np.all(known_bits == filled_bits, axis=0).sum())

    if total == 0:
        return float("-inf")
    prob_weight = math.log(total / number_of_samples, 2)
    return prob_weight


def shared_difference_paired_input_differential_checker_permutation(
    cipher, input_difference, output_difference, number_of_samples, state_size, seed=None, num_workers=1
):
    """
    Verify experimentally shared-difference paired-input differential distinguishers for permutations.

    INPUT:

    - ``cipher`` -- **Cipher object**; permutation instance providing ``evaluate_vectorized``
    - ``input_difference`` -- **integer**; paired input XOR difference
    - ``output_difference`` -- **integer**; expected paired output XOR difference
    - ``number_of_samples`` -- **integer**; number of sampled paired inputs
    - ``state_size`` -- **integer**; permutation state size in bits (must be multiple of 8)
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical probability weight ``log2(matches / number_of_samples)``
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)

    if num_workers > 1:
        total, n = _parallel_dispatch(
            _w_sdpi_diff_perm,
            (cipher, input_difference, output_difference, num_bytes),
            number_of_samples, num_workers, seed,
        )
        return math.log(total / n, 2)

    rng = np.random.default_rng(seed)
    input_difference_data = _repeat_input_difference(input_difference, number_of_samples, num_bytes)
    output_difference_data = _repeat_input_difference(output_difference, number_of_samples, num_bytes)
    plaintext1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data

    plaintext11 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext22 = plaintext11 ^ input_difference_data

    ciphertext1 = cipher.evaluate_vectorized([plaintext1])
    ciphertext2 = cipher.evaluate_vectorized([plaintext2])

    ciphertext11 = cipher.evaluate_vectorized([plaintext11])
    ciphertext22 = cipher.evaluate_vectorized([plaintext22])

    rows_all_true = np.all(
        (ciphertext1[0] ^ ciphertext2[0] ^ ciphertext11[0] ^ ciphertext22[0] == output_difference_data.T), axis=1
    )
    total = np.count_nonzero(rows_all_true)

    total_prob_weight = math.log(total / number_of_samples, 2)
    return total_prob_weight


def shared_difference_paired_input_differential_linear_checker_permutation(
    cipher, input_difference, output_mask, number_of_samples, state_size, seed=None, num_workers=1
):
    """
    Verify experimentally shared-difference paired-input differential-linear distinguishers for permutations.

    INPUT:

    - ``cipher`` -- **Cipher object**; permutation instance providing ``evaluate_vectorized``
    - ``input_difference`` -- **integer**; paired input XOR difference
    - ``output_mask`` -- **string**; output linear mask as a bitstring of length ``state_size``
    - ``number_of_samples`` -- **integer**; number of sampled paired inputs
    - ``state_size`` -- **integer**; permutation state size in bits (must be multiple of 8)
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical correlation in the interval ``[-1, 1]``
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    num_bytes = int(state_size / 8)

    if num_workers > 1:
        count, n = _parallel_dispatch(
            _w_sdpi_diff_linear_perm,
            (cipher, input_difference, output_mask, num_bytes),
            number_of_samples, num_workers, seed,
        )
        return 2 * count / n - 1.0

    rng = np.random.default_rng(seed)
    input_difference_data = _repeat_input_difference(input_difference, number_of_samples, num_bytes)
    bottom_ciphertext_final1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    bottom_ciphertext_final2 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext2 = plaintext1 ^ input_difference_data

    plaintext11 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    plaintext22 = plaintext11 ^ input_difference_data

    ciphertext1 = cipher.evaluate_vectorized([bottom_ciphertext_final1, plaintext1])
    ciphertext2 = cipher.evaluate_vectorized([bottom_ciphertext_final1, plaintext2])

    ciphertext11 = cipher.evaluate_vectorized([bottom_ciphertext_final2, plaintext11])
    ciphertext22 = cipher.evaluate_vectorized([bottom_ciphertext_final2, plaintext22])

    ciphertext3 = ciphertext1[0] ^ ciphertext2[0] ^ ciphertext11[0] ^ ciphertext22[0]
    bit_positions_ciphertext = _extract_bit_positions_msb(output_mask, ("1",))
    ccc = _extract_bits_msb(ciphertext3.T, bit_positions_ciphertext)
    parities = np.bitwise_xor.reduce(ccc, axis=0)
    count = np.count_nonzero(parities == 0)
    corr = 2 * count / number_of_samples * 1.0 - 1
    return corr


def _sample_truncated_difference_from_string(pattern, num_samples, state_size, rng):
    """
    Build a (state_size // 8, num_samples) uint8 matrix with per-sample input differences
    that satisfy the truncated pattern.
    
    Pattern is a string of length = state_size over {'0','1','2','?'}:
      - '0' or '1': fixed bit value
      - '2' or '?': unconstrained (random)
    
    Bit index 0 corresponds to the MSB of the state (MSB-first ordering).
    
    Bits are packed into bytes using big-endian order, i.e., index 0 becomes
    the MSB of byte 0.
    
    Returns:
        A (state_size // 8, num_samples) array of dtype uint8.
    """
    if len(pattern) != state_size:
        raise ValueError(f"pattern length ({len(pattern)}) must equal state_size ({state_size}).")
    if any(c not in ('0','1','2','?') for c in pattern):
        raise ValueError("pattern may only contain '0', '1', '2', or '?'.")

    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")

    # Fixed positions & values (MSB-first indexing)
    indices = np.arange(state_size)
    fixed_mask = np.array([ch in ('0', '1') for ch in pattern], dtype=bool)
    fixed_pos = indices[fixed_mask]
    fixed_vals = np.array([int(ch) for ch in pattern if ch in ('0', '1')], dtype=np.uint8)

    # Generate random bits for all positions, then overwrite fixed ones
    bits = rng.integers(0, 2, size=(num_samples, state_size), dtype=np.uint8)
    if fixed_pos.size:
        bits[:, fixed_pos] = fixed_vals  # broadcast per column

    # Pack bit rows into bytes (big-endian: position 0 = MSB of byte 0)
    input_diff_samples = np.packbits(bits, axis=1, bitorder='big')
    
    return input_diff_samples.T


def differential_truncated_checker_permutation_input_and_output_truncated(
    cipher,
    input_trunc_diff,
    output_trunc_diff,
    number_of_samples,
    state_size,
    seed=None,
    num_workers=1,
):
    """
    Verify experimentally differential-truncated distinguishers for permutations with truncated input and output.

    INPUT:

    - ``cipher`` -- **Cipher object**; permutation instance providing ``evaluate_vectorized``
    - ``input_trunc_diff`` -- **string**; input truncated pattern over ``{'0','1','2','?'}``
    - ``output_trunc_diff`` -- **string**; output truncated pattern over ``{'0','1','2','?'}``
    - ``number_of_samples`` -- **integer**; number of random plaintext pairs
    - ``state_size`` -- **integer**; permutation state size in bits (must be multiple of 8)
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical probability weight, or ``-inf`` if no match is found
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    if len(input_trunc_diff) != state_size or len(output_trunc_diff) != state_size:
        raise ValueError("Both truncated differences must have length == state_size.")

    num_bytes = state_size // 8

    if num_workers > 1:
        total, n = _parallel_dispatch(
            _w_diff_trunc_perm_io,
            (cipher, input_trunc_diff, output_trunc_diff, state_size, num_bytes),
            number_of_samples, num_workers, seed,
        )
        if total == 0:
            return float("-inf")
        return math.log(total / n, 2)

    rng = np.random.default_rng(seed)

    plaintext_data1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    input_mask = _sample_truncated_difference_from_string(input_trunc_diff, number_of_samples, state_size, rng)
    plaintext_data2 = plaintext_data1 ^ input_mask

    ciphertext1 = cipher.evaluate_vectorized([plaintext_data1])[0]
    ciphertext2 = cipher.evaluate_vectorized([plaintext_data2])[0]

    diff_ciphertext = ciphertext1 ^ ciphertext2

    bit_positions = _extract_bit_positions_msb(output_trunc_diff)
    if len(bit_positions) == 0:
        total = number_of_samples
    else:
        known_bits = _extract_bits_msb(diff_ciphertext.T, bit_positions)
        filled_bits = np.array([int(output_trunc_diff[pos]) for pos in bit_positions], dtype=np.uint8)[:, None]
        matches = np.all(known_bits == filled_bits, axis=0)
        total = int(matches.sum())

    if total == 0:
        return float("-inf")
    prob_weight = math.log(total / number_of_samples, 2)
    return prob_weight


def truncated_differential_linear_checker_permutation(
    cipher,
    input_trunc_diff,
    output_mask,
    number_of_samples,
    state_size,
    seed=None,
    num_workers=1,
):
    """
    Verify experimentally truncated-differential-linear distinguishers for permutations.

    INPUT:

    - ``cipher`` -- **Cipher object**; permutation instance providing ``evaluate_vectorized``
    - ``input_trunc_diff`` -- **string**; input truncated pattern over ``{'0','1','2','?'}``
    - ``output_mask`` -- **string**; output linear mask as a bitstring of length ``state_size``
    - ``number_of_samples`` -- **integer**; number of random plaintext pairs
    - ``state_size`` -- **integer**; permutation state size in bits (must be multiple of 8)
    - ``seed`` -- **integer** (default: `None`); seed for reproducible random sampling
    - ``num_workers`` -- **integer** (default: `1`); number of parallel worker processes

    OUTPUT:

    - This method returns a **float**; the empirical correlation in the interval ``[-1, 1]``
    """
    if state_size % 8 != 0:
        raise ValueError("State size must be a multiple of 8.")
    if len(input_trunc_diff) != state_size or len(output_mask) != state_size:
        raise ValueError("Both truncated differences must have length == state_size.")

    num_bytes = state_size // 8

    if num_workers > 1:
        count, n = _parallel_dispatch(
            _w_trunc_diff_linear_perm,
            (cipher, input_trunc_diff, output_mask, state_size, num_bytes),
            number_of_samples, num_workers, seed,
        )
        return 2 * count / n - 1.0

    rng = np.random.default_rng(seed)

    plaintext_data1 = rng.integers(low=0, high=256, size=(num_bytes, number_of_samples), dtype=np.uint8)
    input_mask = _sample_truncated_difference_from_string(input_trunc_diff, number_of_samples, state_size, rng)
    plaintext_data2 = plaintext_data1 ^ input_mask

    ciphertext1 = cipher.evaluate_vectorized([plaintext_data1])
    ciphertext2 = cipher.evaluate_vectorized([plaintext_data2])

    ciphertext3 = ciphertext1[0] ^ ciphertext2[0]
    bit_positions_ciphertext = _extract_bit_positions_msb(output_mask, ("1",))
    ccc = _extract_bits_msb(ciphertext3.T, bit_positions_ciphertext)
    parities = np.bitwise_xor.reduce(ccc, axis=0)
    count = np.count_nonzero(parities == 0)
    corr = 2 * count / number_of_samples * 1.0 - 1
    return corr
