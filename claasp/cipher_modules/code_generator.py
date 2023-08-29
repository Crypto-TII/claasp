
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
import math
import inspect
from subprocess import call

import claasp
from claasp.component import free_input
from claasp.name_mappings import (SBOX, LINEAR_LAYER, MIX_COLUMN, WORD_OPERATION, CONSTANT,
                                  CONCATENATE, PADDING, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT)

tii_path = inspect.getfile(claasp)
tii_dir_path = os.path.dirname(tii_path)

TII_C_LIB_PATH = f'{tii_dir_path}/cipher_modules/'


def delete_generated_evaluate_c_shared_library(cipher):
    name = cipher.id + "_evaluate"
    call(["rm", TII_C_LIB_PATH + name + ".c"])
    call(["rm", TII_C_LIB_PATH + name + ".o"])
    call(["rm", TII_C_LIB_PATH + "generic_bit_based_c_functions.o"])


def generate_bit_based_c_code(cipher, intermediate_output, verbosity):
    code = ['#include <stdio.h>', '#include <stdbool.h>', '#include <stdlib.h>',
            '#include "generic_bit_based_c_functions.h"\n']
    function_args = []
    for cipher_input in cipher.inputs:
        function_args.append(f'BitString *{cipher_input}')
    function_declaration = f'BitString* evaluate({", ".join(function_args)}) {{'
    code.append(function_declaration)

    code.append('\tBitString *input;')
    code.append('\tBitString **input_id;')
    code.append('\tuint16_t **input_positions;')
    code.append('\tuint64_t **matrix;')
    code.append('\tuint64_t *substitution_list;')
    code.append('\tuint8_t **linear_transformation;\n')
    code.extend(get_rounds_bit_based_c_code(cipher, intermediate_output, verbosity))
    code.append('}')
    code.append('int main(int argc, char *argv[]) {')
    evaluate_args = []
    for i in range(len(cipher.inputs)):
        evaluate_args.append(cipher.inputs[i])
        code.append(
            f'\tBitString* {cipher.inputs[i]} = '
            f'bitstring_from_hex_string(argv[{i + 1}], {cipher.inputs_bit_size[i]});')
    code.append(f'\tBitString* output = evaluate({", ".join(evaluate_args)});')
    if not intermediate_output:
        code.append('\tprint_bitstring(output, 16);')
    evaluate_args.append('output')
    code.append(f'\tdelete({", ".join(evaluate_args)});')
    code.append('}')

    return '\n'.join(code)


def get_rounds_bit_based_c_code(cipher, intermediate_output, verbosity):
    c_variables = []
    string_dictionary = {}
    list_sizes = []
    index = 0
    rounds_code = []
    for round_number in cipher.rounds_as_list:
        if verbosity:
            rounds_code.append(f'\tprintf("\\nROUND {round_number.id}\\n\\n");\n')

        for component in round_number.components:
            if component.type in ['constant', 'sbox', 'linear_layer', 'mix_column', 'concatenate']:
                rounds_code.extend(component.get_bit_based_c_code(verbosity))
                c_variables.append(component.id)

            elif component.type == 'word_operation':
                rounds_code.extend(get_word_operation_component_bit_based_c_code(component, verbosity))
                c_variables.append(component.id)

            elif component.type == 'padding':
                rounds_code.extend(get_padding_component_bit_based_c_code(component, verbosity))
                c_variables.append(component.id)

            elif component.type == 'intermediate_output':
                intermediate_output_code, index = get_intermediate_output_component_bit_based_c_code(
                    component, index, intermediate_output, list_sizes, string_dictionary, verbosity)
                rounds_code.extend(intermediate_output_code)
                c_variables.append(component.id)

            elif component.type == 'cipher_output':
                cipher_output_code, index = get_cipher_output_component_bit_based_c_code(
                    component, index, intermediate_output, list_sizes, string_dictionary, c_variables, cipher)
                rounds_code.extend(cipher_output_code)

            else:
                raise ValueError(f'Component {component.id} not implemented.')

    return rounds_code


def get_cipher_output_component_bit_based_c_code(component, index, intermediate_output, list_sizes, string_dictionary,
                                                 c_variables, cipher):
    cipher_output_code = []
    component.select_bits(cipher_output_code)
    if intermediate_output:
        if component.description[0] in string_dictionary:
            list_sizes[string_dictionary[component.description[0]]] += 1

        else:
            string_dictionary[component.description[0]] = index
            list_sizes.append(1)
            index += 1

        s = [f'"{x}"' for x in string_dictionary.keys()]

        number_of_descriptions = len(string_dictionary)

        cipher_output_code.append(f'\tchar **output_list[{number_of_descriptions}];')

        for i in range(len(list_sizes)):
            cipher_output_code.append(f'\tchar *output_list_{i}[{list_sizes[i]}];')
            cipher_output_code.append(f'\toutput_list[{i}] = output_list_{i};')

        list_index = [0] * number_of_descriptions

        for cipher_component in cipher.get_all_components():
            if cipher_component.type == 'intermediate_output':
                i = string_dictionary[cipher_component.description[0]]
                cipher_output_code.append(
                    f'\toutput_list[{i}][{list_index[i]}] = '
                    f'bitstring_to_hex_string({cipher_component.id});')
                list_index[i] += 1

        i = index - 1

        cipher_output_code.append(f'\toutput_list[{i}][{list_index[i]}] = bitstring_to_hex_string(input);')
        list_index[i] += 1

        cipher_output_code.append(f'\tchar *descriptions[] = {{{", ".join(s)}}};')
        cipher_output_code.append(f'\tuint8_t lenghts[] = {{{", ".join([str(x) for x in list_index])}}};')

        cipher_output_code.append('\tprintf("{\\n");')

        cipher_output_code.append(f'\tfor (int i = 0; i < {number_of_descriptions}; i++) {{')
        cipher_output_code.append('\t\tprintf("\\"%s\\" : [", descriptions[i]);')
        cipher_output_code.append('\t\tfor (int j = 0; j < lenghts[i]; j++) {')
        cipher_output_code.append('\t\t\tprintf("%s, ", output_list[i][j]);')
        cipher_output_code.append('\t\t\tfree(output_list[i][j]);')
        cipher_output_code.append('\t\t}')
        cipher_output_code.append('\t\tprintf("],\\n");')
        cipher_output_code.append('\t}')
        cipher_output_code.append('\tprintf("}\\n");')
    cipher_output_code.append(f'\tdelete({", ".join(c_variables)});')
    cipher_output_code.append('\treturn input;')
    return cipher_output_code, index


def get_intermediate_output_component_bit_based_c_code(component, index, intermediate_output, list_sizes,
                                                       string_dictionary, verbosity):
    intermediate_output_code = []
    component.select_bits(intermediate_output_code)
    intermediate_output_code.append(f'\tBitString *{component.id} = input;')
    if intermediate_output:
        if component.description[0] in string_dictionary:
            list_sizes[string_dictionary[component.description[0]]] += 1

        else:
            string_dictionary[component.description[0]] = index
            list_sizes.append(1)
            index += 1
    if verbosity:
        component.print_values(intermediate_output_code)
    return intermediate_output_code, index


def get_padding_component_bit_based_c_code(component, verbosity):
    padding_code = []
    component.select_bits(padding_code)
    padding_code.append(f'\tBitString* {component.id} = PADDING(input, {component.output_bit_size});\n')
    if verbosity:
        component.print_values(padding_code)
    free_input(padding_code)

    return padding_code


def get_word_operation_component_bit_based_c_code(component, verbosity):
    word_operation_code = []
    component.select_bits(word_operation_code)
    if component.description[0] in ['SHIFT', 'ROTATE', 'SHIFT_BY_VARIABLE_AMOUNT', 'ROTATE_BY_VARIABLE_AMOUNT']:
        word_operation_code.append(
            f'\tBitString *{component.id} = {component.description[0]}('
            f'input, {component.output_bit_size}, {component.description[1]});')
    else:
        word_operation_code.append(
            f'\tBitString *{component.id} = {component.description[0]}('
            f'input, {component.output_bit_size});')
    if verbosity:
        component.print_values(word_operation_code)
    free_input(word_operation_code)

    return word_operation_code


def generate_bit_based_vectorized_python_code_string(cipher, store_intermediate_outputs=False,
                                                     verbosity=False, convert_output_to_bytes=False):
    """
    Return string python code needed to evaluate a cipher using a vectorized implementation bit based oriented.

    INPUT:

    - ``cipher`` -- **Cipher object**; a cipher instance
    - ``store_intermediate_outputs`` -- **boolean** (default: `False`); set this flag to True in order to return a list
      with each round output
    - ``verbosity`` -- **boolean** (default: `False`); set to True to make the Python code print the input/output of
      each component
    - ``convert_output_to_bytes`` -- **boolean** (default: `False`)

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules import code_generator
        sage: speck = SpeckBlockCipher()
        sage: string_python_code = code_generator.generate_bit_based_vectorized_python_code_string(speck)
        sage: string_python_code.split("\n")[0]
        'from claasp.cipher_modules.generic_functions_vectorized_bit import *'
    """
    code = ['from claasp.cipher_modules.generic_functions_vectorized_bit import *\n',
            'def evaluate(input, store_intermediate_outputs):', '  intermediateOutputs={}']

    code.extend([f'  {cipher.inputs[i]}=input[{i}]' for i in range(len(cipher.inputs))])
    for component in cipher.get_all_components():
        params = prepare_input_bit_based_vectorized_python_code_string(component)
        component_types_allowed = ['constant', 'linear_layer', 'concatenate', 'mix_column',
                                   'sbox', 'cipher_output', 'intermediate_output']
        component_descriptions_allowed = ['ROTATE', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT', 'NOT', 'XOR',
                                          'MODADD', 'MODSUB', 'OR', 'AND']
        if component.type in component_types_allowed or (component.type == 'word_operation' and
                                                         component.description[0] in component_descriptions_allowed):
            code.extend(component.get_bit_based_vectorized_python_code(params, convert_output_to_bytes))
        name = component.id
        if verbosity and component.type != 'constant':
            code.append(f'  bit_vector_print_as_hex_values("{name}_output", {name})')
    if store_intermediate_outputs:
        code.append('  return intermediateOutputs')
    else:
        code.append('  return intermediateOutputs["cipher_output"]')

    return '\n'.join(code)


def prepare_input_bit_based_vectorized_python_code_string(component):
    params = [
        f'bit_vector_select_word({component.input_id_links[i]},  {component.input_bit_positions[i]})'
        for i in range(len(component.input_id_links))]

    return params


def constant_to_bitstring(val, output_size):
    ret = []
    _val = int(val, 0)
    for i in range(output_size):
        ret.append((_val >> (output_size - 1 - i)) & 1)

    return ret


def generate_byte_based_vectorized_python_code_string(cipher, store_intermediate_outputs=False, verbosity=False):
    r"""
    Return string python code needed to evaluate a cipher using a vectorized implementation byte based oriented.

    INPUT:

    - ``cipher`` -- **Cipher object**; a cipher instance
    - ``store_intermediate_outputs`` -- **boolean** (default: `False`); set this flag to True in order to return a list
      with each round output
    - ``verbosity`` -- **boolean** (default: `False`); set to True to make the Python code print the input/output of
      each component

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules import code_generator
        sage: speck = SpeckBlockCipher()
        sage: string_python_code = code_generator.generate_byte_based_vectorized_python_code_string(speck)
        sage: string_python_code.split("\n")[0]
        'from claasp.cipher_modules.generic_functions_vectorized_byte import *'
    """
    cipher.sort_cipher()

    code = ['from claasp.cipher_modules.generic_functions_vectorized_byte import *\n', '\n',
            'def evaluate(input, store_intermediate_outputs):', '  intermediateOutputs={}']
    bit_sizes = {}
    for i in range(len(cipher.inputs)):
        code.append(f'  {cipher.inputs[i]}=input[{i}]')
        bit_sizes[cipher.inputs[i]] = cipher.inputs_bit_size[i]
    for component in cipher.get_all_components():
        params = prepare_input_byte_based_vectorized_python_code_string(bit_sizes, component)
        bit_sizes[component.id] = component.output_bit_size
        component_types_allowed = ['constant', 'linear_layer', 'concatenate', 'mix_column',
                                   'sbox', 'cipher_output', 'intermediate_output']
        component_descriptions_allowed = ['ROTATE', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT', 'NOT', 'XOR',
                                          'MODADD', 'MODSUB', 'OR', 'AND']
        if component.type in component_types_allowed or (component.type == 'word_operation' and
                                                         component.description[0] in component_descriptions_allowed):
            code.extend(component.get_byte_based_vectorized_python_code(params))

        name = component.id

        if verbosity and component.type != 'constant':
            code.append(f'  byte_vector_print_as_hex_values("{name}_input", {params})')
            code.append(f'  byte_vector_print_as_hex_values("{name}_output", {name})')
    if store_intermediate_outputs:
        code.append('  return intermediateOutputs')
    else:
        code.append('  return intermediateOutputs["cipher_output"]')

    return '\n'.join(code)


def prepare_input_byte_based_vectorized_python_code_string(bit_sizes, component):
    params = None
    initial_inputs = component.input_id_links
    bits = component.input_bit_positions
    number_of_inputs = get_number_of_inputs(component)
    input_bit_size = component.input_bit_size
    if component.type == 'constant':
        return params

    bits_per_input = input_bit_size // number_of_inputs
    words_per_input = math.ceil(bits_per_input / 8)
    # Divide inputs
    real_inputs = [[] for _ in range(number_of_inputs)]
    real_bits = [[] for _ in range(number_of_inputs)]
    bits_read = 0
    inputs_read = 0
    cpt_inputs = 0
    pos_in_input = 0

    while inputs_read < number_of_inputs:
        needed_bits = bits_per_input - bits_read
        remaining_bits = len(bits[cpt_inputs]) - pos_in_input
        if remaining_bits == needed_bits:
            real_inputs[inputs_read].append(cpt_inputs)
            real_bits[inputs_read].append(bits[cpt_inputs][pos_in_input:])
            inputs_read += 1
            cpt_inputs += 1
            bits_read = 0
            pos_in_input = 0
        elif remaining_bits > needed_bits:
            real_inputs[inputs_read].append(cpt_inputs)
            real_bits[inputs_read].append(bits[cpt_inputs][pos_in_input:(pos_in_input + needed_bits)])
            inputs_read += 1
            bits_read = 0
            pos_in_input += needed_bits
        elif remaining_bits < needed_bits:
            real_inputs[inputs_read].append(cpt_inputs)
            real_bits[inputs_read].append(bits[cpt_inputs][pos_in_input:])
            bits_read += len(bits[cpt_inputs][pos_in_input:])
            cpt_inputs += 1
            pos_in_input = 0
    actual_input_size = [bit_sizes[x] for x in component.input_id_links]
    params = f'byte_vector_select_all_words([{",".join(initial_inputs)}], ' \
             f'{real_bits}, {real_inputs}, {number_of_inputs}, ' \
             f'{words_per_input}, {actual_input_size})'

    is_good = True
    if len(initial_inputs) == number_of_inputs:
        for i in range(number_of_inputs):
            if bits[i] != list(range(actual_input_size[i])):
                is_good = False
        if is_good:
            params = f'[{",".join(initial_inputs)}]'

    return params


def get_number_of_inputs(component):
    number_of_inputs = None
    if component.type == 'word_operation':
        description = component.description[0]
        if description in {'ROTATE', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT', 'NOT'}:
            number_of_inputs = 1
        else:
            number_of_inputs = component.description[1]
    elif component.type == 'mix_column':
        number_of_inputs = len(component.description[0])
    elif component.type == 'linear_layer':
        number_of_inputs = len(component.description[0])
    elif component.type == 'sbox':
        number_of_inputs = 1
    elif component.type == 'concatenate':
        number_of_inputs = 1
    elif 'output' in component.type:
        number_of_inputs = 1

    return number_of_inputs


def constant_to_repr(val, output_size):
    _val = int(val, 0)
    if output_size % 8 != 0:
        s = output_size + (8 - (output_size % 8))
    else:
        s = output_size
    ret = [(_val >> s - (8 * (i + 1))) & 0xff for i in range(s // 8)]

    return ret


def generate_evaluate_c_code_shared_library(cipher, intermediate_output, verbosity):
    name = cipher.id + "_evaluate"
    cipher_word_size = cipher.is_power_of_2_word_based()
    if cipher_word_size:
        if not os.path.exists(TII_C_LIB_PATH + f"generic_word_{cipher_word_size}_based_c_functions.o"):
            call(["gcc", "-w", "-c", TII_C_LIB_PATH + "generic_word_based_c_functions.c", "-o", TII_C_LIB_PATH +
                  f"generic_word_{cipher_word_size}_based_c_functions.o", "-D", f"word_size={cipher_word_size}"])

        f = open(TII_C_LIB_PATH + name + ".c", "w+")
        f.write(cipher.generate_word_based_c_code(cipher_word_size, intermediate_output, verbosity))
        f.close()

        call(["gcc",
              "-w",
              TII_C_LIB_PATH + f"generic_word_{cipher_word_size}_based_c_functions.o",
              TII_C_LIB_PATH + name + ".c",
              "-o",
              TII_C_LIB_PATH + name + ".o",
              "-D",
              f"word_size={cipher_word_size}"])

    else:
        generic_bit_based_c_functions_o_file = "generic_bit_based_c_functions.o"
        if not os.path.exists(TII_C_LIB_PATH + generic_bit_based_c_functions_o_file):
            call(["gcc", "-w", "-c", TII_C_LIB_PATH + "generic_bit_based_c_functions.c",
                  "-o", TII_C_LIB_PATH + generic_bit_based_c_functions_o_file])

        f = open(TII_C_LIB_PATH + name + ".c", "w+")
        f.write(cipher.generate_bit_based_c_code(intermediate_output, verbosity))
        f.close()

        call(["gcc", "-w", TII_C_LIB_PATH + generic_bit_based_c_functions_o_file,
              TII_C_LIB_PATH + name + ".c", "-o", TII_C_LIB_PATH + name + ".o"])


def generate_python_code_string(cipher, verbosity=False):
    r"""
    Return a string containing the python code that defines the self.evaluate() method.

    INPUT:

    - ``cipher`` -- **Cipher object**; a cipher instance
    - ``verbosity`` -- **boolean** (default: `False`); set to True to make the Python code print the input/output of
      each component

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
        sage: from claasp.cipher_modules import code_generator
        sage: fancy = FancyBlockCipher()
        sage: string_python_code = code_generator.generate_python_code_string(fancy)
        sage: "def evaluate(input):" in string_python_code
        True

        # This test is skipped due to it changes the order of the intermediate outputs sometimes as:
        # intermediate_output['cipher_output'] = []
        # intermediate_output['round_key_output'] = []
        sage: from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
        sage: from claasp.cipher_modules import code_generator
        sage: identity = IdentityBlockCipher()
        sage: print(code_generator.generate_python_code_string(identity, verbosity=True)) # doctest: +SKIP
        from copy import copy
        from bitstring import BitArray
        from claasp.cipher_modules.generic_functions import *
        <BLANKLINE>
        def evaluate(input):
            plaintext_output = copy(BitArray(uint=input[0], length=32))
            key_output = copy(BitArray(uint=input[1], length=32))
            intermediate_output = {}
            intermediate_output['round_key_output'] = []
            intermediate_output['cipher_output'] = []
            components_io = {}
            component_input = BitArray(1)
            print('\nRound_0\n')
        <BLANKLINE>
            # round: 0, component: 0, component_id: concatenate_0_0
            component_input = select_bits(key_output, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])
            output_bit_size = 32
            concatenate_0_0_output = component_input
            components_io['concatenate_0_0'] = [component_input.uint, concatenate_0_0_output.uint]
            print('concatenate_0_0_input = {}'.format(component_input))
            print('concatenate_0_0_output = {}'.format(concatenate_0_0_output))
        ...
        <BLANKLINE>
            # round: 0, component: 3, component_id: cipher_output_0_3
            component_input = select_bits(concatenate_0_2_output, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])
            output_bit_size = 32
            cipher_output_0_3_output = component_input
            intermediate_output['cipher_output'].append(cipher_output_0_3_output.uint)
            cipher_output = cipher_output_0_3_output.uint
            components_io['cipher_output_0_3'] = [component_input.uint, cipher_output_0_3_output.uint]
            print('cipher_output_0_3_input = {}'.format(component_input))
            print('cipher_output_0_3_output = {}'.format(cipher_output_0_3_output))
        <BLANKLINE>
            return cipher_output, intermediate_output, components_io
        <BLANKLINE>
    """

    cipher.sort_cipher()

    cipher_code_string = "from copy import copy\n"
    cipher_code_string += "from bitstring import BitArray\n"
    cipher_code_string += "from claasp.cipher_modules.generic_functions import *\n"
    cipher_code_string += "\n"
    cipher_code_string += "def evaluate(input):\n"

    for i in range(len(cipher.inputs)):
        cipher_code_string += "    " + cipher.inputs[i] + "_output = copy(BitArray(uint=int(input[" + \
                              str(i) + "]), length=" + str(
            cipher.inputs_bit_size[i]) + "))\n"

    cipher_code_string += "    intermediate_output = {}\n"

    intermediate_output = set()
    number_of_rounds = cipher.number_of_rounds
    for cipher_round in cipher.rounds_as_list:
        for component in cipher_round.components:
            if component.type == INTERMEDIATE_OUTPUT or \
                    component.type == CIPHER_OUTPUT:
                intermediate_output.add(component.description[0])

    for int_out in intermediate_output:
        cipher_code_string += "    intermediate_output['" + int_out + "'] = []\n"

    cipher_code_string += "    components_io = {}\n"

    # initialize component input for the first constant component
    cipher_code_string += "    component_input = BitArray(1)\n"

    for i in range(number_of_rounds):
        if verbosity:
            cipher_code_string += "    print('\\nRound_" + str(i) + "\\n')\n"

        cipher_code_string = build_code_for_components(cipher, cipher_code_string, i, verbosity)

    cipher_code_string += "\n    return cipher_output, intermediate_output, components_io\n"

    return cipher_code_string


def build_code_for_components(cipher, cipher_code_string, i, verbosity):
    for j in range(cipher.get_number_of_components_in_round(i)):
        cipher_code_string += "\n    # round: {}, component: {}, component_id: {}".format(
            i, j, cipher.component_from(i, j).id) + "\n"
        component = cipher.component_from(i, j)

        # build input (if constant no input is needed)
        if component.type != CONSTANT:
            tmp = ["select_bits(" + component.input_id_links[input_bit_positions_counter] +
                   "_output, " + str(component.input_bit_positions[input_bit_positions_counter]) +
                   ")" for input_bit_positions_counter in range(len(component.input_id_links))]
            component_input = " + ".join(tmp)
            cipher_code_string += "    component_input = " + component_input + "\n"
        else:
            cipher_code_string += "    component_input = BitArray(1)\n"

        # set output
        cipher_code_string += "    output_bit_size = " + str(component.output_bit_size) + "\n"

        function_call_as_string = build_function_call(component)
        component_id_output = component.id + "_output"
        cipher_code_string += "    " + component_id_output + " = " + function_call_as_string + "\n"

        if component.type == INTERMEDIATE_OUTPUT or component.type == CIPHER_OUTPUT:
            cipher_code_string += "    intermediate_output['" + \
                                  component.description[0] + "'].append(" + component_id_output + ".uint)\n"

        if component.type == CIPHER_OUTPUT:
            cipher_code_string += "    cipher_output = " + component_id_output + ".uint\n"

        cipher_code_string += "    components_io['" + component.id + \
                              "'] = [component_input.uint, " + component_id_output + ".uint]\n"

        if verbosity:
            cipher_code_string += "    print('" + component.id + "_input = {}'.format(component_input))\n"
            cipher_code_string += "    print('" + component.id + \
                                  "_output = {}'.format(" + component.id + "_output))\n"
    return cipher_code_string


def build_function_call(component):
    if component.type == SBOX:
        sbox_table = component.description
        return f"sbox(component_input, {sbox_table}, output_bit_size)"
    elif component.type == LINEAR_LAYER:
        linear_layer_matrix = component.description
        return f"linear_layer(component_input, {linear_layer_matrix})"
    elif component.type == MIX_COLUMN:
        mix_column_matrix = component.description[0]
        polynomial = component.description[1]
        word_size = component.description[2]
        return f"mix_column_generalized(component_input, {mix_column_matrix}, {polynomial}, {word_size})"
    elif component.type == WORD_OPERATION:
        if component.description[0] in ('SHIFT_BY_VARIABLE_AMOUNT', 'ROTATE_BY_VARIABLE_AMOUNT'):
            return f"{component.description[0]}" \
                   f"(component_input, {component.output_bit_size}, {component.description[1]})"
        elif component.description[0] == 'NOT':
            return f"{component.description[0]}(component_input)"
        else:
            return f"{component.description[0]}(component_input, {component.description[1]})"
    elif component.type == CONSTANT:
        return f"set_from_hex_string('{component.description[0]}')"
    elif component.type == CONCATENATE:
        return "component_input"
    elif component.type == PADDING:
        return "padding(component_input)"
    elif component.type == INTERMEDIATE_OUTPUT:
        return "component_input"
    elif component.type == CIPHER_OUTPUT:
        return "component_input"
    else:
        raise NotImplementedError("Component not implemented yet")


def generate_python_code_string_for_continuous_diffusion_analysis(cipher, verbosity=False):
    """
    Return a string containing the python code that defines a self.evaluate_continuous_diffusion_analysis() method.

    INPUT:

    - ``cipher`` -- **Cipher object**; a cipher instance
    - ``verbosity`` -- **boolean** (default: `False`); set to True to make the Python code print the input/output of
      each component

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules import code_generator
        sage: speck = SpeckBlockCipher(number_of_rounds=2)
        sage: string_python_code = code_generator.generate_python_code_string_for_continuous_diffusion_analysis(speck, verbosity=False)
        sage: "def evaluate(input):" in string_python_code
        True
    """

    number_of_rounds = cipher.number_of_rounds

    cipher.sort_cipher()
    add_verbosity = verbosity
    cipher_code_string = \
        "from claasp.cipher_modules.generic_functions_continuous_diffusion_analysis import *\n"
    cipher_code_string += "\n"
    cipher_code_string += "def evaluate(input):\n"
    # initialize inputs
    cipher_code_string += "".join(f"    {cipher_input}_output = input[{round_number}]\n"
                                  for round_number, cipher_input in enumerate(cipher.inputs))

    cipher_code_string += "    intermediate_output = {}\n"
    intermediate_output = set()

    for component in cipher.get_all_components():
        if component.type in (INTERMEDIATE_OUTPUT, CIPHER_OUTPUT):
            intermediate_output.add(component.description[0])
    cipher_code_string += "".join(f"    intermediate_output['{int_out}'] = []\n" for int_out in intermediate_output)

    for round_number in range(number_of_rounds):
        if add_verbosity:
            cipher_code_string += f"    print('\\nRound_{round_number}\\n')\n"

        cipher_code_string = build_code_for_continuous_diffusion_analysis_components(add_verbosity, cipher,
                                                                                     cipher_code_string, round_number)

    cipher_code_string += "\n    return cipher_output, intermediate_output\n"

    return cipher_code_string


def build_code_for_continuous_diffusion_analysis_components(add_verbosity, cipher, cipher_code_string, round_number):
    for component_number in range(cipher.get_number_of_components_in_round(round_number)):
        cipher_code_string += \
            f"\n    # round: {round_number}, component: {component_number}, " \
            f"component_id: {cipher.component_from(round_number, component_number).id}\n"
        component = cipher.component_from(round_number, component_number)

        # build input (if constant no input is needed)
        if component.type != CONSTANT:
            tmp = [
                f"select_bits_continuous_diffusion_analysis({id_link}_output, {bit_positions})" for id_link,
                bit_positions in zip(component.input_id_links, component.input_bit_positions)]
            cipher_code_string += f"    component_input = {' + '.join(tmp)}\n"

        _function = build_continuous_diffusion_analysis_function_call(component)
        component_id_output = f"{component.id}_output"
        cipher_code_string += f"    {component_id_output} = {_function}\n"

        if component.type in (INTERMEDIATE_OUTPUT, CIPHER_OUTPUT):
            cipher_code_string += \
                f"    intermediate_output['{component.description[0]}']" \
                f".append({{'intermediate_output': {component_id_output}, 'round': {round_number + 1}}})\n"

        if component.type == CIPHER_OUTPUT:
            cipher_code_string += f"    cipher_output = {component_id_output}\n"  # + ".uint\n"

        if add_verbosity and component.type != CONSTANT:
            cipher_code_string += f"    print(f'{component.id}_input = {{component_input}}')\n"
            cipher_code_string += f"    print(f'{component.id}_output = {{{component.id}_output}}')\n"
    return cipher_code_string


def build_continuous_diffusion_analysis_function_call(component):
    if component.type == SBOX:
        sbox_table = component.description
        return (
            f'SBOX_continuous_diffusion_analysis('
            f'component_input, sbox_precomputations["{sbox_table}"]'
            f')'
        )
    elif component.type == LINEAR_LAYER:
        linear_layer_matrix = component.description
        return f"LINEAR_LAYER_continuous_diffusion_analysis(component_input, {linear_layer_matrix})"
    elif component.type == MIX_COLUMN:
        mix_column_matrix = component.description[0]
        word_size = component.description[2]
        return (
            f'MIX_COLUMN_generalized_continuous_diffusion_analysis('
            f'component_input, {mix_column_matrix}, '
            f'sbox_precomputations_mix_columns["{component.description}"], '
            f'{word_size})'
        )
    elif component.type == WORD_OPERATION:
        description = component.description[1]
        if component.description[0] in ('SHIFT_BY_VARIABLE_AMOUNT', 'ROTATE_BY_VARIABLE_AMOUNT'):
            description = f"{component.output_bit_size}, {component.description[1]}"
        if component.description[0] == 'NOT':
            return f"{component.description[0]}_continuous_diffusion_analysis(component_input)"
        else:
            return f"{component.description[0]}_continuous_diffusion_analysis(component_input, {description})"
    elif component.type == CONSTANT:
        return f"CONSTANT_continuous_diffusion_analysis({component.description[0]}, " \
               f"{component.output_bit_size})"
    elif component.type in [CONCATENATE, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT]:
        return "component_input"
    elif component.type == PADDING:
        return "padding(component_input)"
    else:
        raise NotImplementedError("Continuous Diffusion Analysis component not implemented yet")


def generate_word_based_c_code(cipher, word_size, intermediate_output, verbosity):
    code = ['#include <stdio.h>', '#include <stdbool.h>', '#include <stdlib.h>',
            '#include "generic_word_based_c_functions.h"\n']
    function_args = []
    for cipher_input in cipher.inputs:
        function_args.append(f'WordString *{cipher_input}')
    function_declaration = f'WordString* evaluate({", ".join(function_args)}) {{'
    code.append(function_declaration)
    code.append('\tWordString input_struct = {')
    code.append('\t\t.list = NULL,')
    code.append('\t\t.string_size = 0')
    code.append('\t};')
    code.append('\tWordString *input = &input_struct;')
    if verbosity:
        code.append('\tchar *str;')
    code.extend(get_rounds_word_based_c_code(cipher, intermediate_output, verbosity, word_size))
    code.append('}')
    code.append('int main(int argc, char *argv[]) {')
    evaluate_args = []
    for i in range(len(cipher.inputs)):
        evaluate_args.append(cipher.inputs[i])
        code.append(f'\tWordString* {cipher.inputs[i]} = '
                    f'wordstring_from_hex_string(argv[{i + 1}], '
                    f'{cipher.inputs_bit_size[i] // word_size});')
    code.append(f'\tWordString* output = evaluate({", ".join(evaluate_args)});')
    if not intermediate_output:
        code.append('\tprint_wordstring(output, 16);')
    evaluate_args.append('output')
    code.append(f'\tdelete({", ".join(evaluate_args)});')
    code.append('}')

    return '\n'.join(code)


def get_rounds_word_based_c_code(cipher, intermediate_output, verbosity, word_size):
    rounds_code = []
    wordstring_variables = []
    string_dictionary = {}
    list_sizes = []
    intermediate_output_code = []
    index = 0
    for round_number in cipher.rounds_as_list:
        if verbosity:
            rounds_code.append(f'\tprintf("\\nROUND {round_number.id}\\n\\n");\n')
        for component in round_number.components:
            is_shift_or_rotate_component = component.type == 'word_operation' and \
                                           component.description[0] in ['SHIFT', 'ROTATE',
                                                                        'SHIFT_BY_VARIABLE_AMOUNT',
                                                                        'ROTATE_BY_VARIABLE_AMOUNT']
            if component.type in ['constant', 'sbox', 'concatenate'] or is_shift_or_rotate_component:
                rounds_code.extend(component.get_word_based_c_code(verbosity, word_size, wordstring_variables))
            elif component.type == 'word_operation':
                rounds_code.extend(get_word_operation_word_based_c_code(component, verbosity,
                                                                        word_size, wordstring_variables))
            elif component.type == 'intermediate_output':
                component_code, index = get_intermediate_output_word_based_c_code(
                    component, index, intermediate_output, intermediate_output_code, list_sizes,
                    string_dictionary, verbosity, word_size, wordstring_variables)
                rounds_code.extend(component_code)
            elif component.type == 'cipher_output':
                component_code, index = get_cipher_output_word_based_c_code(
                    component, index, intermediate_output, intermediate_output_code, list_sizes,
                    string_dictionary, verbosity, word_size, wordstring_variables)
                rounds_code.extend(component_code)
            else:
                raise ValueError(f'Component {component.id} not available.')

    return rounds_code


def get_cipher_output_word_based_c_code(component, index, intermediate_output, intermediate_output_code,
                                        list_sizes, string_dictionary, verbosity, word_size, wordstring_variables):
    code = []
    component.select_words(code, word_size, False)
    output = component.id
    if verbosity:
        code.append(f'\tstr = wordstring_to_hex_string({component.id});')
        code.append(f'\tprintf("{component.id} input: %s\\n", str);')
        code.append(f'\tprintf("{component.id} output: %s\\n", str);')
        code.append('\tfree(str);')
    if intermediate_output:
        update_intermediate_structure(string_dictionary, list_sizes, intermediate_output_code, component, index)
        number_of_descriptions = len(string_dictionary)
        description_list = [''] * number_of_descriptions
        for description, index in string_dictionary.items():
            description_list[index] = f'"{description}"'
        code.append(f'\tchar **output_list[{number_of_descriptions}];')
        for i in range(len(list_sizes)):
            code.append(f'\tchar *output_list_{i}[{list_sizes[i]}];')
            code.append(f'\toutput_list[{i}] = output_list_{i};')
        code.extend(intermediate_output_code)
        code.append(f'\tchar *descriptions[] = {{{", ".join(description_list)}}};')
        code.append(f'\tuint8_t lenghts[] = {{{", ".join([str(x) for x in list_sizes])}}};')
        code.append('\tprintf("{");')
        code.append(f'\tfor (int i = 0; i < {number_of_descriptions}; i++) {{')
        code.append('\t\tprintf("\\"%s\\" : [", descriptions[i]);')
        code.append('\t\tfor (int j = 0; j < lenghts[i]; j++) {')
        code.append('\t\t\tprintf("%s, ", output_list[i][j]);')
        code.append('\t\t\tfree(output_list[i][j]);')
        code.append('\t\t}')
        code.append('\t\tprintf("],\\n");')
        code.append('\t}')
        code.append('\tprintf("}");')
    code.append(f'\tdelete({", ".join(wordstring_variables)});')
    code.append(f'\treturn {output};')

    return code, index


def get_intermediate_output_word_based_c_code(component, index, intermediate_output, intermediate_output_code,
                                              list_sizes, string_dictionary, verbosity, word_size,
                                              wordstring_variables):
    code = []
    component.select_words(code, word_size, False)
    wordstring_variables.append(component.id)
    if verbosity:
        code.append(f'\tstr = wordstring_to_hex_string({component.id});')
        code.append(f'\tprintf("{component.id} input: %s\\n", str);')
        code.append(f'\tprintf("{component.id} output: %s\\n", str);')
        code.append('\tfree(str);')
    if intermediate_output and component.type == 'intermediate_output':
        index = update_intermediate_structure(string_dictionary, list_sizes, intermediate_output_code,
                                              component, index)
    return code, index


def get_word_operation_word_based_c_code(component, verbosity, word_size, wordstring_variables):
    word_operation_code = []
    component.select_words(word_operation_code, word_size)
    wordstring_variables.append(component.id)
    word_operation_code.append(f'\tWordString *{component.id} = {component.description[0]}(input);')
    if verbosity:
        component.print_word_values(word_operation_code)

    return word_operation_code


def update_intermediate_structure(string_dictionary, list_sizes, intermediate_output_code, component, index):
    component_description = component.description[0]

    if component_description in string_dictionary:
        i = string_dictionary[component_description]
        list_sizes[i] += 1

    else:
        string_dictionary[component_description] = index
        list_sizes.append(1)
        i = index
        index += 1

    intermediate_output_code.append(
        f'\toutput_list[{i}][{list_sizes[i] - 1}] = wordstring_to_hex_string({component.id});')

    return index
