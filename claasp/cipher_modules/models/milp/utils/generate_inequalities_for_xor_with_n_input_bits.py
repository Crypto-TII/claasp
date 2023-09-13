
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
The target of this module is to generate MILP inequalities for a XOR operation between n input bits.
"""
import pickle, os, pathlib
import subprocess

file_name = "dictionary_containing_xor_inequalities_between_n_input_bits.obj"

xor_inequalities_between_n_input_bits_file_path = os.path.join(pathlib.Path(__file__).parent.resolve(), file_name)


def generate_all_possible_points_with_n_bits(number_of_bits):
    all_possible_points = []
    tmp = []
    for integer in range(1 << number_of_bits):
        for index in range(number_of_bits):
            tmp.append((integer & (1 << index)) >> index)
        all_possible_points.append(tmp)
        tmp = []

    return all_possible_points


def generate_impossible_points_for_xor_between_n_input_bits(number_of_bits):
    all_possible_points = generate_all_possible_points_with_n_bits(number_of_bits + 1)
    impossible_points = []
    for point in all_possible_points:
        if sum(point) % 2 == 1:
            impossible_points.append("".join([str(i) for i in point]))

    return impossible_points


def update_dictionary_that_contains_xor_inequalities_between_n_input_bits(number_of_input_bits):
    dictio = output_dictionary_that_contains_xor_inequalities()

    if number_of_input_bits not in dictio.keys():
        print(f"Adding xor inequalities between {number_of_input_bits} input bits in pre-saved dictionary")
        dictio[number_of_input_bits] = generate_impossible_points_for_xor_between_n_input_bits(number_of_input_bits)
        write_file = open(
            xor_inequalities_between_n_input_bits_file_path,
            'wb')
        pickle.dump(dictio, write_file)
        write_file.close()


def update_dictionary_that_contains_xor_inequalities_for_specific_matrix(mat):
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
        update_dictionary_that_contains_xor_inequalities_between_n_input_bits(number_of_input_bits)


def output_dictionary_that_contains_xor_inequalities():
    try:
        read_file = open(xor_inequalities_between_n_input_bits_file_path, 'rb')
        dictio = pickle.load(read_file)
        read_file.close()
    except (OSError, EOFError):
        dictio = {}
    return dictio


def delete_dictionary_that_contains_xor_inequalities():
    write_file = open(xor_inequalities_between_n_input_bits_file_path, 'wb')
    pickle.dump({}, write_file)
    write_file.close()