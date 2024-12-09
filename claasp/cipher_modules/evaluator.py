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


import numpy as np
from types import ModuleType
from subprocess import Popen, PIPE

from claasp.cipher_modules import code_generator

def evaluate(cipher, cipher_input, intermediate_output=False, verbosity=False):
    python_code_string = code_generator.generate_python_code_string(cipher, verbosity)

    f_module = ModuleType("evaluate")
    exec(python_code_string, f_module.__dict__)

    if intermediate_output:
        return f_module.evaluate(cipher_input)

    return f_module.evaluate(cipher_input)[0]


def evaluate_using_c(cipher, inputs, intermediate_output, verbosity):
    cipher.generate_evaluate_c_code_shared_library(intermediate_output, verbosity)
    name = cipher.id + "_evaluate"
    c_cipher_inputs = [hex(value) for value in inputs]
    process = Popen([code_generator.TII_C_LIB_PATH + name + ".o"] + c_cipher_inputs, stdout=PIPE)
    output = process.stdout

    if verbosity and intermediate_output:
        line = output.readline().decode('utf-8')

        while line != '{\n':
            print(line[:-1].decode('utf-8'))
            line = output.readline().decode('utf-8')

        dict_str = line

        for line in output.readlines():
            dict_str += line.decode('utf-8')

        function_output = eval(dict_str)
    elif verbosity and not intermediate_output:
        output_lines = output.readlines()
        for line in output_lines[:-1]:
            print(line[:-1].decode('utf-8'))

        function_output = int(output_lines[-1].decode('utf-8')[:-1], 16)
    elif intermediate_output:
        dict_str = ''

        for line in output.readlines():
            dict_str += line.decode('utf-8')

        function_output = eval(dict_str)
    else:
        function_output = int(output.read().decode('utf-8')[:-1], 16)

    code_generator.delete_generated_evaluate_c_shared_library(cipher)

    return function_output


def evaluate_vectorized(cipher, cipher_input, intermediate_output=False, verbosity=False, evaluate_api=False,
                        bit_based=False):
    python_code_string = code_generator.generate_byte_based_vectorized_python_code_string(cipher,
                                                                                              store_intermediate_outputs=intermediate_output,
                                                                                              verbosity=verbosity,
                                                                                              integers_inputs_and_outputs=evaluate_api)
    f_module = ModuleType("evaluate")
    exec(python_code_string, f_module.__dict__)
    cipher_output = f_module.evaluate(cipher_input, intermediate_output)
    return cipher_output


def evaluate_with_intermediate_outputs_continuous_diffusion_analysis(cipher, cipher_input, sbox_precomputations,
                                                                     sbox_precomputations_mix_columns, verbosity=False):
    python_code_string = code_generator.generate_python_code_string_for_continuous_diffusion_analysis(cipher, verbosity)
    python_code_string = python_code_string.replace(
        "def evaluate(input):", "def evaluate(input, sbox_precomputations, sbox_precomputations_mix_columns):")

    f_module = ModuleType("evaluate_continuous_diffusion_analysis")
    exec(python_code_string, f_module.__dict__)

    return f_module.evaluate(cipher_input, sbox_precomputations, sbox_precomputations_mix_columns)
