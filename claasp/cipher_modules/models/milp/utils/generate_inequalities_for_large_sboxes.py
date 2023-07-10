
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
The target of this module is to generate MILP inequalities for small and large sboxes (4 - 8 bits) by using espresso.

The logic minimizer espresso is required for this module. It is already installed in the docker.
"""
import pickle, os, pathlib
import subprocess

from sage.rings.integer_ring import ZZ

large_sbox_file_name = "dictionary_that_contains_inequalities_for_large_sboxes.obj"
large_sbox_xor_linear_file_name = "dictionary_that_contains_inequalities_for_large_sboxes_xor_linear.obj"

large_sboxes_inequalities_file_path = os.path.join(pathlib.Path(__file__).parent.resolve(), large_sbox_file_name)
large_sboxes_xor_linear_inequalities_file_path = os.path.join(pathlib.Path(__file__).parent.resolve(),
                                                             large_sbox_xor_linear_file_name)


def generate_espresso_input(input_size, output_size, value, valid_transformations_matrix):
    # little_endian
    def to_bits(x):
        return ZZ(x).digits(base=2, padto=input_size)[::-1]

    espresso_input = [f"# there are {input_size + output_size} input variables\n"]
    espresso_input.append(f".i {input_size + output_size}")
    espresso_input.append("# there is only 1 output result\n")
    espresso_input.append(".o 1\n")
    espresso_input.append("# the following is the truth table\n")

    n, m = input_size, output_size
    for i in range(0, 1 << n):
        for o in range(0, 1 << m):
            io = "".join([str(i) for i in to_bits(i) + to_bits(o)])
            if i + o > 0 and valid_transformations_matrix[i][o] == value:
                espresso_input.append(f"{io} 1\n")
            else:
                espresso_input.append(f"{io} 0\n")

    espresso_input.append("# end of the PLA data\n")
    espresso_input.append(".e")

    return ''.join(espresso_input)

def generate_product_of_sum_from_espresso(sbox, analysis="differential"):

    dict_espresso_outputs = {}
    if analysis == "differential":
        valid_transformations_matrix = sbox.difference_distribution_table()
        values_in_matrix = list(set(valid_transformations_matrix.coefficients()))
        values_in_matrix.remove(pow(2, sbox.input_size()))
    elif analysis == "linear":
        valid_transformations_matrix = sbox.linear_approximation_table()
        values_in_matrix = list(set(valid_transformations_matrix.coefficients()))
        values_in_matrix.remove(pow(2, sbox.input_size() - 1))
    else:
        raise TypeError("analysis (%s) has to be one of ['differential', 'linear']" % (analysis,))

    for value in values_in_matrix:
        espresso_input = generate_espresso_input(sbox.input_size(), sbox.output_size(), value, valid_transformations_matrix)
        espresso_process = subprocess.run(['espresso', '-epos', '-okiss'], input=espresso_input,
                                          capture_output=True, text=True)
        espresso_output = espresso_process.stdout.splitlines()
        dict_espresso_outputs[value] = [line[:-2] for line in espresso_output[4:]]

    return dict_espresso_outputs


def get_dictionary_that_contains_inequalities_for_large_sboxes(analysis="differential"):
    """
    Require Espresso to be installed.

    It returns a dictionary containing the minimized set of inequalities representing the DDT of a Sbox,
    using the method described in https://tosc.iacr.org/index.php/ToSC/article/view/805/759:

    - first, the DDT is separated into multiple tables so that each pb-DDT table only contains entries
      with the same probability pb
    - then Espresso is used to compute the minimum product-of-sum representation of each pb-DDT,
      seen as a boolean function
    """
    file_path = large_sboxes_inequalities_file_path if analysis == "differential" else large_sboxes_xor_linear_inequalities_file_path

    read_file = open(file_path, 'rb')
    inequalities = pickle.load(read_file)
    read_file.close()
    return inequalities


def update_dictionary_that_contains_inequalities_for_large_sboxes(sbox, analysis="differential"):

    file_path = large_sboxes_inequalities_file_path if analysis == "differential" else large_sboxes_xor_linear_inequalities_file_path

    try:
        read_file = open(file_path, 'rb')
        dictio = pickle.load(read_file)
        read_file.close()
    except OSError:
        dictio = {}

    if str(sbox) not in dictio.keys():
        print("Adding sbox inequalities in pre-saved dictionary")
        dict_product_of_sum = generate_product_of_sum_from_espresso(sbox, analysis)
        dictio[str(sbox)] = dict_product_of_sum

        write_file = open(file_path, 'wb')
        pickle.dump(dictio, write_file)
        write_file.close()


def delete_dictionary_that_contains_inequalities_for_large_sboxes(analysis="differential"):
    file_path = large_sboxes_inequalities_file_path if analysis == "differential" else large_sboxes_xor_linear_inequalities_file_path
    write_file = open(file_path, 'wb')
    pickle.dump({}, write_file)
    write_file.close()
