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

The target of this module is to generate MILP inequalities for a wordwise truncated XOR operation between n input words.

"""
import itertools
from math import ceil, log
import pickle, os, pathlib
from functools import reduce
from subprocess import run


input_patterns_file_name = "dictionary_containing_truncated_xor_inequalities_between_2_input_bits.obj"
xor_n_inputs_file_name = "dictionary_containing_truncated_xor_inequalities_between_n_input_bits.obj"
wordwise_truncated_input_pattern_inequalities_file_path = os.path.join(pathlib.Path(__file__).parent.resolve(), input_patterns_file_name)
wordwise_truncated_xor_inequalities_between_n_input_bits_file_path = os.path.join(pathlib.Path(__file__).parent.resolve(), xor_n_inputs_file_name)



def generate_valid_points_input_words(wordsize=4, max_pattern_value=3):
    """
        Model 1 from https://tosc.iacr.org/index.php/ToSC/article/view/8702/8294

        delta | zeta
        ------------
          0   |  Z (0)
          1   |  N (> 0)
          2   |  N*
          3   |  U


    """

    bit_len = ceil(log(max_pattern_value))
    valid_points = []

    if max_pattern_value == 3:

        list_of_possible_inputs = [(0, 0)] + \
                                  [(1, i) for i in range(1, 1 << wordsize)] + \
                                  [(2, 0)] + [(3, 0)]

        for delta, zeta in list_of_possible_inputs:
            tmp = ''.join(format(delta, '0' + str(bit_len) + 'b') +
                          format(zeta, '0' + str(wordsize) + 'b'))
            valid_points.append(tmp)
    else:
        raise NotImplementedError

    return valid_points


def update_dictionary_that_contains_wordwise_truncated_input_inequalities(wordsize):
    try:
        read_file = open(wordwise_truncated_input_pattern_inequalities_file_path, 'rb')
        dictio = pickle.load(read_file)
        read_file.close()
    except:
        dictio = {}

    if wordsize not in dictio.keys():
        print(f"Adding inequalities for truncated words of size {wordsize} bits in pre-saved dictionary")
        valid_points = generate_valid_points_input_words(wordsize)
        inequalities = generate_product_of_sum_from_espresso(valid_points)
        dictio[wordsize] = inequalities
        write_file = open(wordwise_truncated_input_pattern_inequalities_file_path, 'wb')
        pickle.dump(dictio, write_file)
        write_file.close()


def output_dictionary_that_contains_wordwise_truncated_input_inequalities():
    read_file = open(wordwise_truncated_input_pattern_inequalities_file_path, 'rb')
    dictio = pickle.load(read_file)
    read_file.close()
    return dictio


def delete_dictionary_that_contains_wordwise_truncated_input_inequalities():
    write_file = open(wordwise_truncated_input_pattern_inequalities_file_path, 'wb')
    pickle.dump({}, write_file)
    write_file.close()


def get_valid_points_for_wordwise_xor(delta_in_1, zeta_in_1, delta_in_2, zeta_in_2):

    zeta_out = 0
    if delta_in_1 + delta_in_2 > 2:
        delta_out = 3
    elif delta_in_1 + delta_in_2 == 1:
        delta_out = 1
        zeta_out = zeta_in_1 + zeta_in_2
    elif delta_in_1 == 0 and delta_in_2 == 0:
        delta_out = 0
    elif zeta_in_1 + zeta_in_2 < 0:
        delta_out = 2
    elif zeta_in_1 == zeta_in_2:
        delta_out = 0
    else:
        delta_out = 1
        zeta_out = zeta_in_1 ^ zeta_in_2

    return delta_out, zeta_out

def generate_valid_points_for_xor_between_n_input_words(wordsize=4, number_of_words=2):
    """
        Model 2 from https://tosc.iacr.org/index.php/ToSC/article/view/8702/8294
    """

    bit_len = 2
    valid_points = []

    if wordsize == 1:
        for in1 in range(3):
            for in2 in range(3):
                if in1 < 2 and in2 < 2:
                    res = (in1 + in2) % 2
                else:
                    res = 2
                full_array = ZZ(res).digits(base=2, padto=bit_len) + ZZ(in2).digits(base=2, padto=bit_len) + ZZ(in1).digits(base=2, padto=bit_len)
                valid_points.append("".join(str(_) for _ in full_array[::-1]))

    else:

        list_of_possible_inputs = [(0, 0)] + \
                                  [(1, i) for i in range(1, 1 << wordsize)] + \
                                  [(2, -1)] + [(3, -2)]


        for input in itertools.product(list_of_possible_inputs, repeat=number_of_words):
            delta = [input[_][0] for _ in range(number_of_words)]
            zeta = [input[_][1] for _ in range(number_of_words)]

            tmp_delta = [0 for _ in range(number_of_words - 1)]
            tmp_zeta = [0 for _ in range(number_of_words - 1)]
            tmp_delta[0] = delta[0]
            tmp_zeta[0] = zeta[0]


            for summand in range(number_of_words - 2):
                tmp_delta[summand + 1], tmp_zeta[summand + 1] = get_valid_points_for_wordwise_xor(tmp_delta[summand], tmp_zeta[summand], delta[summand + 1], zeta[summand + 1])

            delta_output, zeta_output = get_valid_points_for_wordwise_xor(tmp_delta[-1], tmp_zeta[-1], delta[-1], zeta[-1])

            if delta.count(3) == 0 and delta.count(2) == 1 and delta.count(1) > 1:
                only_fixed_patterns = [i[1] for i in enumerate(zeta) if delta[i[0]] == 1]
                if len(only_fixed_patterns) > 1:
                    if reduce(lambda a, b: a ^ b, only_fixed_patterns) == 0:
                        delta_output = 2
                    else:
                        delta_output = 3

            tmp = ''.join(format(delta[i], '0' + str(bit_len) + 'b') +
                          format(zeta[i] if (delta[i] == 1) else 0, '0' + str(wordsize) + 'b') for i in range(number_of_words)) + \
                  format(delta_output, '0' + str(bit_len) + 'b') + \
                  format(zeta_output, '0' + str(wordsize) + 'b')

            valid_points.append(tmp)

    return valid_points


def update_dictionary_that_contains_wordwise_truncated_xor_inequalities_between_n_inputs(wordsize, number_of_inputs):
    try:
        read_file = open(wordwise_truncated_xor_inequalities_between_n_input_bits_file_path, 'rb')
        dictio = pickle.load(read_file)
        read_file.close()
    except:
        dictio = {}

    if wordsize not in dictio.keys():
        dictio[wordsize] = {}

    if number_of_inputs not in dictio[wordsize].keys():
        print(
            f"Adding wordwise xor inequalities between {number_of_inputs} inputs of size {wordsize} in pre-saved dictionary")
        valid_points = generate_valid_points_for_xor_between_n_input_words(wordsize, number_of_inputs)
        inequalities = generate_product_of_sum_from_espresso(valid_points)
        dictio[wordsize][number_of_inputs] = inequalities
        write_file = open(wordwise_truncated_xor_inequalities_between_n_input_bits_file_path, 'wb')
        pickle.dump(dictio, write_file)
        write_file.close()


def update_dictionary_that_contains_xor_inequalities_for_specific_wordwise_matrix(wordsize, mat):
    number_of_1_in_each_cols = []
    for i in range(len(mat[0])):
        number_of_1 = 0
        col = [row[i] for row in mat]
        for bit in col:
            if bit:
                number_of_1 += 1
        if number_of_1 > 1:
            number_of_1_in_each_cols.append(number_of_1)
    number_of_1_in_each_cols = list(set(number_of_1_in_each_cols))
    for number_of_input_bits in number_of_1_in_each_cols:
        update_dictionary_that_contains_wordwise_truncated_xor_inequalities_between_n_inputs(wordsize, number_of_input_bits)

def output_dictionary_that_contains_wordwise_truncated_xor_inequalities():
    read_file = open(wordwise_truncated_xor_inequalities_between_n_input_bits_file_path, 'rb')
    dictio = pickle.load(read_file)
    read_file.close()
    return dictio


def delete_dictionary_that_contains_wordwise_truncated_xor_inequalities():
    write_file = open(wordwise_truncated_xor_inequalities_between_n_input_bits_file_path, 'wb')
    pickle.dump({}, write_file)
    write_file.close()


def generate_espresso_input(valid_points):
    """
    For the wordwise truncated xor, the file is:

    # there are 6 input variables
    .i 6# there is only 1 output result
    .o 1
    # the following is the truth table
    000000 1
    000101 1
    001010 1
    001111 1
    010001 1
    010100 1
    010101 1
    011011 1
    011111 1
    100010 1
    100111 1
    101011 1
    101111 1
    110011 1
    110111 1
    111011 1
    111111 1
    # end of the PLA data
    .e

    """

    input_size = len(valid_points[0])

    espresso_input = [f"# there are {input_size} input variables\n"]
    espresso_input.append(f".i {input_size}")
    espresso_input.append("# there is only 1 output result\n")
    espresso_input.append(".o 1\n")
    espresso_input.append("# the following is the truth table\n")

    for point in valid_points:
        espresso_input.append(f"{point} 1\n")

    espresso_input.append("# end of the PLA data\n")
    espresso_input.append(".e")

    return ''.join(espresso_input)


def generate_product_of_sum_from_espresso(valid_points):

    espresso_input = generate_espresso_input(valid_points)
    espresso_process = run(['espresso', '-epos', '-okiss'], input=espresso_input,
                                          capture_output=True, text=True)
    espresso_output = espresso_process.stdout.splitlines()

    return [line[:-2] for line in espresso_output[4:]]