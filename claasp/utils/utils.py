
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


import json
import pprint
import random
import numpy as np
from copy import deepcopy
from decimal import Decimal
from random import randrange
from collections import defaultdict, Counter


from sage.rings.integer_ring import IntegerRing

from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY


def aggregate_list_of_dictionary(dataset, group_by_key, sum_value_keys):
    """
    Aggregate by `group_by_key` the list of objects in `dataset` by summing_up the values in `sum_value_keys`.

    INPUT:

    - ``dataset`` -- **list of dictionaries**
    - ``group_by_key`` -- **string**
    - ``sum_value_keys`` -- **list**

    EXAMPLES::

        sage: from claasp.utils.utils import aggregate_list_of_dictionary
        sage: from collections import Counter
        sage: import datetime
        sage: my_dataset = [
        ....:     {
        ....:         'date': datetime.date(2013, 1, 1),
        ....:         'id': 99,
        ....:         'value1': 10,
        ....:         'value2': 10
        ....:     },
        ....:     {
        ....:         'date': datetime.date(2013, 1, 1),
        ....:         'id': 98,
        ....:         'value1': 10,
        ....:         'value2': 10
        ....:     },
        ....:     {
        ....:         'date': datetime.date(2013, 1, 2),
        ....:         'id': 99,
        ....:         'value1': 10,
        ....:         'value2': 10
        ....:     }
        ....: ]
        sage: expected_output = {
        ....:      datetime.date(2013, 1, 2): Counter({'value2': 10, 'value1': 10}),
        ....:      datetime.date(2013, 1, 1): Counter({'value2': 20, 'value1': 20})
        ....: }
        sage: aggregate_list_of_dictionary(my_dataset, 'date', ['value1', 'value2']) == expected_output
        True
    """
    dic = defaultdict(Counter)
    for item in dataset:
        key = item[group_by_key]
        values = {k: item[k] for k in sum_value_keys}
        dic[key].update(values)

    return dic


def bytes_positions_to_little_endian_for_32_bits(lst):
    r"""
    Read the bytes positions in little-endian order.

    INPUT:

    - ``lst`` -- **list**

    EXAMPLES::

        sage: from claasp.utils.utils import bytes_positions_to_little_endian_for_32_bits
        sage: lst = list(range(32))
        sage: output_lst = [24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7]
        sage: bytes_positions_to_little_endian_for_32_bits(lst) == output_lst
        True
    """

    temp_lst = []
    for j in range(4):
        temp_lst += lst[(3 - j) * 8:(3 - j) * 8 + 8]

    return temp_lst


def bytes_positions_to_little_endian_for_multiple_of_32(lst, number_of_blocks):
    output_lst = []
    for block_number in range(number_of_blocks):
        temp_lst = lst[block_number * 32:block_number * 32 + 32]
        temp2_lst = bytes_positions_to_little_endian_for_32_bits(temp_lst)
        output_lst.append(temp2_lst)

    return output_lst


def calculate_inputs(planes, plane_num=3, lane_num=4):
    inputs_id = []
    inputs_pos = []
    for i in range(plane_num):
        if type(planes[i].id[0]) is list:
            for j in range(lane_num):
                inputs_id = inputs_id + planes[i].id[j]
                inputs_pos = inputs_pos + planes[i].input_bit_positions[j]
        else:
            inputs_id = inputs_id + planes[i].id
            inputs_pos = inputs_pos + planes[i].input_bit_positions

    return inputs_id, inputs_pos


def convert_2d_index_to_1d_index(i, array_dim):
    return i // array_dim, i % array_dim


def create_new_state_for_calculation(plane_num=3):
    planes_new = []
    for _ in range(plane_num):
        plane = ComponentState([[], [], [], []], [[], [], [], []])
        planes_new.append(deepcopy(plane))

    return planes_new


def extract_inputs(input_ids_list, input_bit_positions_list, bit_positions_to_be_extracted):
    input_ids_sublist = []
    input_bit_positions_sublist = []

    position_list = []
    input_bit_size = len(input_bit_positions_list[0])
    j = 0

    for i in bit_positions_to_be_extracted:
        if i >= input_bit_size:
            if position_list:
                input_ids_sublist.append(input_ids_list[j])
                input_bit_positions_sublist.append(position_list)

                position_list = []

            while i >= input_bit_size:
                input_bit_size += len(input_bit_positions_list[j + 1])
                j += 1

        position_list.append(input_bit_positions_list[j][i - (input_bit_size - len(input_bit_positions_list[j]))])

    input_ids_sublist.append(input_ids_list[j])
    input_bit_positions_sublist.append(position_list)

    return input_ids_sublist, input_bit_positions_sublist


def generate_sample_from_gf_2_n(n, number_of_samples=100):
    while True:
        a = np.random.choice([0, 1], size=(number_of_samples, n))
        if len(np.unique(a, axis=0)) == number_of_samples:
            break

    return a


def get_2d_array_element_from_1d_array_index(i, lst, array_dim):
    return lst[i // array_dim][i % array_dim]


def get_ci(i, qi, si, t):
    q = qi[(i % 7)]
    s = si[(i % 6)]
    ci = t ** s * (q + t ** 3)
    _ci = ci.change_ring(IntegerRing())

    return _ci(2)


def get_inputs_parameter(inputs_list):
    inputs_id = []
    inputs_pos = []
    for k in inputs_list:
        inputs_id += deepcopy(k.id)
        inputs_pos += deepcopy(k.input_bit_positions)

    inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)

    return inputs_id, inputs_pos


def get_ith_word(word_size, i, id_str=None, lst_by_id=""):
    input_types = [INPUT_KEY, INPUT_PLAINTEXT]
    if id_str in input_types and lst_by_id != "":
        return lst_by_id[0]

    return list(range(i * word_size, i * word_size + word_size))


def get_number_of_rounds_from(block_bit_size, key_bit_size, number_of_rounds, parameters_configurations):
    if number_of_rounds == 0:
        n = None
        for parameters in parameters_configurations:
            if parameters['block_bit_size'] == block_bit_size and parameters['key_bit_size'] == key_bit_size:
                n = parameters['number_of_rounds']
                break
        if n is None:
            raise ValueError("No available number of rounds for the given parameters.")
    else:
        n = number_of_rounds

    return n


def get_k_th_bit(n, k):
    """
    Return the k-th bit of the number n.

    INPUT:

    - ``n`` -- **integer**; integer number
    - ``k`` -- **integer**; integer number representing the index of the bit we need

    EXAMPLES::

        sage: from claasp.utils.utils import get_k_th_bit
        sage: get_k_th_bit(3, 0)
        1
    """
    return 1 & (n >> k)


def group_list_by_key(lst):
    """
    Group list of dictionaries by key.

    INPUT:

    - ``lst`` -- **list**; list of dictionaries

    EXAMPLES::

        sage: from claasp.utils.utils import group_list_by_key
        sage: lst_example = [{'cipher_output': [{'1': 0}]}, {'round_key_output': [{'1': 0}]}, {'round_key_output': [{'3': 0}]}, {'cipher_output': [{'2': 0}]}, {'round_key_output': [{'2': 0}]}, {'cipher_output': [{'4': 0}]}]
        sage: group_list_by_key(lst_example)
        defaultdict(<class 'list'>, {'cipher_output': [[{'1': 0}], [{'2': 0}], [{'4': 0}]], 'round_key_output': [[{'1': 0}], [{'3': 0}], [{'2': 0}]]})
    """
    from collections import defaultdict
    joint_results_objects_group_by_tag_output = defaultdict(list)
    for value in lst:
        for key, item in value.items():
            joint_results_objects_group_by_tag_output[key].append(item)

    return joint_results_objects_group_by_tag_output


def int_to_poly(integer_value, word_size, variable):
    z = 0
    for i in range(word_size):
        if (integer_value >> i) & 1:
            z = z + pow(variable, i)

    return z


def layer_and_lane_initialization(plane_num=3, lane_num=4, lane_size=32):
    planes = []
    plane_size = lane_num * lane_size
    for i in range(plane_num):
        p = ComponentState([INPUT_PLAINTEXT for _ in range(lane_num)],
                           [[k + j * lane_size + i * plane_size for k in range(lane_size)]
                            for j in range(lane_num)])
        planes.append(p)

    return planes


def merging_list_of_lists(lst):
    """
    Merge list of lists.

    INPUT:

    - ``lst`` -- **list**; list of lists

    EXAMPLES::

        sage: from claasp.utils.utils import merging_list_of_lists
        sage: merging_list_of_lists([[1,2],[3,4]])
        [1, 2, 3, 4]
    """
    import itertools

    return list(itertools.chain(*lst))


def pprint_dictionary(dictionary):
    r"""
    Pretty-print of a dictionary.

    INPUT:

    - ``dictionary`` -- **dictionary**

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
        sage: from claasp.utils.utils import pprint_dictionary
        sage: tests_configuration = {"diffusion_tests": {"run_tests": True, "number_of_samples": 100,
        ....:     "run_avalanche_dependence": True, "run_avalanche_dependence_uniform": True,
        ....:     "run_avalanche_weight": True, "run_avalanche_entropy": True,
        ....:     "avalanche_dependence_uniform_bias": 0.2, "avalanche_dependence_criterion_threshold": 0,
        ....:     "avalanche_dependence_uniform_criterion_threshold":0, "avalanche_weight_criterion_threshold": 0.1,
        ....:     "avalanche_entropy_criterion_threshold":0.1}, "component_analysis_tests": {"run_tests": True}
        ....: }
        sage: cipher = IdentityBlockCipher()
        sage: analysis = cipher.analyze_cipher(tests_configuration)
        sage: pprint_dictionary(analysis['diffusion_tests']['input_parameters'])
        {   'avalanche_dependence_criterion_threshold': 0,
        'avalanche_dependence_uniform_bias': 0.200000000000000,
        'avalanche_dependence_uniform_criterion_threshold': 0,
        'avalanche_entropy_criterion_threshold': 0.100000000000000,
        'avalanche_weight_criterion_threshold': 0.100000000000000,
        'number_of_samples': 100}
    """
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(dictionary)


def pprint_dictionary_to_file(dictionary, name_file):
    r"""
    Pretty-print of a dictionary.

    INPUT:

    - ``dictionary`` -- **dictionary**
    - ``name_file`` -- **string**

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
        sage: from claasp.utils.utils import pprint_dictionary_to_file
        sage: cipher = IdentityBlockCipher()
        sage: tests_configuration = {"diffusion_tests": {"run_tests": True, "number_of_samples": 100,
        ....:     "run_avalanche_dependence": True, "run_avalanche_dependence_uniform": True,
        ....:     "run_avalanche_weight": True, "run_avalanche_entropy": True,
        ....:     "avalanche_dependence_uniform_bias": 0.2, "avalanche_dependence_criterion_threshold": 0,
        ....:     "avalanche_dependence_uniform_criterion_threshold":0, "avalanche_weight_criterion_threshold": 0.1,
        ....:     "avalanche_entropy_criterion_threshold":0.1}, "component_analysis_tests": {"run_tests": True}
        ....: }
        sage: import inspect
        sage: import claasp
        sage: tii_path = inspect.getfile(claasp)
        sage: tii_dir_path = os.path.dirname(tii_path)
        sage: analysis = cipher.analyze_cipher(tests_configuration)
        sage: pprint_dictionary_to_file(analysis['diffusion_tests']['input_parameters'], f"{tii_dir_path}/test_json")
        sage: import os.path
        sage: os.path.isfile(f"{tii_dir_path}/test_json")
        True

        sage: import os
        sage: os.remove(f"{tii_dir_path}/test_json")
    """
    dictionary_json = json.loads(str(dictionary).replace("'", '"'))
    source_file = open(name_file, 'w')
    print(json.dumps(dictionary_json, indent=4), file=source_file)
    source_file.close()


def set_2d_array_element_from_1d_array_index(i, lst, element, array_dim):
    lst[i // array_dim][i % array_dim] = element


def sgn_function(x):
    """
    Implement the sign function.

    INPUT:

    - ``x`` -- **float**; real number

    EXAMPLES::

        sage: from claasp.utils.utils import sgn_function
        sage: sgn_function(-1)
        -1
    """
    if x < 0:
        return -1

    return 1


def signed_distance(lst_x, lst_y):
    """
    Implement Definition 13 (signed distance function) that is in [MUR2020]_.

    INPUT:

    - ``lst_x`` -- **list**; list of real numbers
    - ``lst_y`` -- **list**; list of real numbers

    EXAMPLES::

        sage: from claasp.utils.utils import signed_distance
        sage: lst_x = [0.001, -0.99]
        sage: lst_y = [0.002, -0.90]
        sage: signed_distance(lst_x, lst_y)
        0
    """
    n = len(lst_x)

    return sum([abs(sgn_function(lst_x[i]) - sgn_function(lst_y[i])) for i in range(n)])


def simplify_inputs(inputs_id, inputs_pos):
    inputs_id_new = [inputs_id[0]]
    inputs_pos_new = [deepcopy(inputs_pos[0])]
    for i in range(1, len(inputs_id)):
        if inputs_id[i] == inputs_id_new[-1]:
            inputs_pos_new[-1] += inputs_pos[i]
        else:
            inputs_id_new += [inputs_id[i]]
            inputs_pos_new += [inputs_pos[i]]

    return inputs_id_new, inputs_pos_new


def point_pair(dist=0.001, dim=1):
    """
    Return a pair of lists $x, y$ of length `dim` where all elements are equal to 1 except one of them.

    The non-one element is chosen randomly.

    Also, the Euclidean distance between $x$ and $y$ is less than `dim`. And the non-one element of $x$ is taking
    from $U(low,high)$.

    INPUT:

    - ``dist`` -- **float** (default: `0.001`); real number use to bound the Euclidean distance between $x$ and $y$
    - ``dim`` -- **integer** (default: `1`); length of the list $x$ and $y$

    EXAMPLES::

        sage: from claasp.utils.utils import point_pair
        sage: point_pair(0.001, 1) # random
    """
    one_minus_one = [Decimal(-1), Decimal(1)]
    x_list = []
    for _ in range(dim):
        x_list.append(one_minus_one[random.randrange(0, 2)])
    y_list = deepcopy(x_list)

    delta = np.random.uniform(-dist, dist)
    random_bit = randrange(dim)
    y_list[random_bit] = x_list[random_bit] + Decimal(delta)

    return x_list, y_list


def poly_to_int(polynom, word_size, a):
    str_poly = str(polynom)
    str_poly = str_poly.split(" + ")
    binary_lst = []
    for i in range(word_size):
        tmp = a ** i
        if str(tmp) in str_poly:
            binary_lst.append("1")
        else:
            binary_lst.append("0")
    binary_lst.reverse()
    output = "".join(binary_lst)
    output = int("0b" + output, base=2)

    return output

