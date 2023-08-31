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


"""

The target of this module is to generate MILP inequalities for a wordwise truncated MDS operation between m input words,
using model 5 from https://tosc.iacr.org/index.php/ToSC/article/view/8702/8294

"""
from itertools import product
from math import ceil, log
import pickle, os, pathlib
from claasp.cipher_modules.models.milp.utils import utils as milp_utils

wordwise_truncated_mds_file_name = "dictionary_containing_truncated_mds_inequalities.obj"
wordwise_truncated_mds_file_path = os.path.join(pathlib.Path(__file__).parent.resolve(), wordwise_truncated_mds_file_name)



def generate_valid_points_for_truncated_mds_matrix(dimensions=(4,4), max_pattern_value=3):
    """
        Model 5 from https://tosc.iacr.org/index.php/ToSC/article/view/8702/8294
    """

    nrows, ncols = dimensions
    bit_len = ceil(log(max_pattern_value))
    valid_points = []

    if max_pattern_value == 3:
        list_of_possible_deltas = range(max_pattern_value)

        for delta in product(list_of_possible_deltas, repeat=ncols):
            if sum(delta) == 0:
                delta_output = [0 for _ in range(nrows)]
            elif (sum(delta) == 1) or (sum(delta) == 2 and delta.count(2) == 1):
                delta_output = [2 for _ in range(nrows)]
            else:
                delta_output = [3 for _ in range(nrows)]

            tmp = ''.join(format(delta[i], '0' + str(bit_len) + 'b')  for i in range(ncols)) + \
                  ''.join(format(delta_output[i], '0' + str(bit_len) + 'b') for i in range(nrows))
            valid_points.append(tmp)
    else:
        raise NotImplementedError


    return valid_points


def update_dictionary_that_contains_wordwise_truncated_mds_inequalities(wordsize=8, dimensions=(4,4)):
    try:
        read_file = open(wordwise_truncated_mds_file_path, 'rb')
        dictio = pickle.load(read_file)
        read_file.close()
    except OSError:
        dictio = {}

    if wordsize not in dictio.keys():
        dictio[wordsize] = {}

    if dimensions not in dictio[wordsize].keys():
        print(
            f"Adding wordwise mds inequalities for {dimensions[0]} x {dimensions[1]} matrices for words of {wordsize} bits in pre-saved dictionary")
        valid_points = generate_valid_points_for_truncated_mds_matrix(dimensions)
        inequalities = milp_utils.generate_product_of_sum_from_espresso(valid_points)
        dictio[wordsize][dimensions] = inequalities
        write_file = open(wordwise_truncated_mds_file_path, 'wb')
        pickle.dump(dictio, write_file)
        write_file.close()


def output_dictionary_that_contains_wordwise_truncated_mds_inequalities():
    return milp_utils.output_espresso_dictionary(wordwise_truncated_mds_file_path)


def delete_dictionary_that_contains_wordwise_truncated_mds_inequalities():
    return milp_utils.delete_espresso_dictionary(wordwise_truncated_mds_file_path)
