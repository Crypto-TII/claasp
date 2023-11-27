
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


import yaml
from os import listdir


def get_cipher(cipher_module):
    for name in cipher_module.__dict__:
        if 'BlockCipher' in name or 'HashFunction' in name or 'Permutation' in name:
            return cipher_module.__dict__[name]

    return 0


def get_ciphers():
    ciphers_files = listdir('claasp/ciphers/block_ciphers')
    ciphers_files.extend(listdir('claasp/ciphers/permutations'))
    ciphers_files.extend(listdir('claasp/ciphers/hash_functions'))
    ciphers_files.extend(listdir('claasp/ciphers/stream_ciphers'))
    ciphers_files = list(set(ciphers_files))
    ciphers = [cipher for cipher in ciphers_files if get_cipher_type(cipher)]
    return ciphers


def make_cipher_id(cipher_family_name, inputs, inputs_bit_size, output_bit_size):
    cipher_id = f'{cipher_family_name}'
    for i in range(len(inputs)):
        cipher_id = cipher_id + "_" + inputs[i][0] + str(inputs_bit_size[i])
    cipher_id = cipher_id + "_o" + str(output_bit_size)

    return cipher_id


def create_scenario_string(scenario_dict):
    final = []
    conversions = {">": "greater", "=": "equal", ">=": "greater_or_equal"}
    for key, value in scenario_dict.items():
        final.append(f'{key}_{conversions[value]}')
    final.sort()

    return "_".join(final)


def load_parameters(file_path):
    with open(file_path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


def get_cipher_type(cipher_filename):
    cipher_type = ""
    if "block_cipher" in cipher_filename:
        cipher_type = "block_ciphers"
    elif "permutation" in cipher_filename:
        cipher_type = "permutations"
    elif "hash_function" in cipher_filename:
        cipher_type = "hash_functions"
    elif "stream_cipher" in cipher_filename:
        cipher_type = "stream_ciphers"

    return cipher_type
