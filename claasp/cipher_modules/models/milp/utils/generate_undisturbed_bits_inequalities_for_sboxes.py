
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
The target of this module is to generate MILP inequalities for small s-boxes (up to 5 bits) for the bitwise deterministic
truncated xor differential model,  by using espresso.
It uses the notion of undisturbed differential bits discussed in https://link.springer.com/chapter/10.1007/978-3-031-26553-2_3


The logic minimizer espresso is required for this module. It is already installed in the docker.
"""
import pickle
import subprocess

from sage.rings.integer_ring import ZZ

undisturbed_bit_sboxes_inequalities_file_path = \
    "./claasp/cipher_modules/models/milp/dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits.obj"

def generate_espresso_input(valid_points):
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

def get_transitions_for_single_output_bit(sbox, valid_points):

    def to_bits(x, input_size):
        return ZZ(x).digits(base=2, padto=input_size)[::-1]
    def encode_transition(delta_in, delta_out):
        encoded_in = [_ for j in delta_in for _ in to_bits(j, 2)]
        encoded_out = [_ for j in delta_out for _ in to_bits(j, 2)]
        # print_transition(delta_in, delta_out, True)
        return "".join(str(_) for _ in encoded_in + encoded_out)

    def print_transition(delta_in, delta_out, print_undisturbed_only=False):
        input_str = ''.join(['1' if _ == 1 else '0' if _ == 0 else '?' for _ in delta_in])
        output_str = ''.join(['1' if _ == 1 else '0' if _ == 0 else '?' for _ in delta_out])
        if print_undisturbed_only:
            if output_str != ''.join(['?' for _ in delta_out]):
                print(f"     {input_str} -> {output_str}")
        else:
            print(f"     {input_str} -> {output_str}")

    ddt_with_undisturbed_bits_transitions = [encode_transition(input, output) for input, output in valid_points]
    n = sbox.input_size()

    valid_points = {}
    for position in range(n):
        valid_points[position] = {}
        for encoding_bit in range(2):
            valid_points[position][encoding_bit] = [transition[:2 * n] + transition[2 * (n + position) + encoding_bit] for transition in ddt_with_undisturbed_bits_transitions]

    return valid_points


def generate_product_of_sum_from_espresso(sbox, valid_points):

    dict_espresso_outputs = {}
    valid_transitions = get_transitions_for_single_output_bit(sbox, valid_points)

    for position in valid_transitions:
        dict_espresso_outputs[position] = {}
        for encoding_bit in valid_transitions[position]:
            valid_bit_transitions = valid_transitions[position][encoding_bit]
            espresso_input = generate_espresso_input(valid_bit_transitions)
            espresso_process = subprocess.run(['espresso', '-epos', '-okiss'], input=espresso_input,
                                              capture_output=True, text=True)
            espresso_output = espresso_process.stdout.splitlines()
            dict_espresso_outputs[position][encoding_bit] = [line[:-2] for line in espresso_output[4:]]

    return dict_espresso_outputs


def get_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits():
    """
    Require Espresso to be installed.

    """
    file_path = undisturbed_bit_sboxes_inequalities_file_path

    read_file = open(file_path, 'rb')
    inequalities = pickle.load(read_file)
    read_file.close()
    return inequalities

def update_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits(sbox, valid_points):

    file_path = undisturbed_bit_sboxes_inequalities_file_path

    try:
        read_file = open(file_path, 'rb')
        dictio = pickle.load(read_file)
        read_file.close()
    except OSError:
        dictio = {}

    if str(sbox) not in dictio.keys():
        print("Adding sbox inequalities in pre-saved dictionary")
        dict_product_of_sum = generate_product_of_sum_from_espresso(sbox, valid_points)
        dictio[str(sbox)] = dict_product_of_sum

        write_file = open(file_path, 'wb')
        pickle.dump(dictio, write_file)
        write_file.close()


def delete_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits():
    file_path = undisturbed_bit_sboxes_inequalities_file_path
    write_file = open(file_path, 'wb')
    pickle.dump({}, write_file)
    write_file.close()
