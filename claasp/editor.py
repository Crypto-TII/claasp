import sys
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


from copy import deepcopy
from itertools import chain

import networkx as nx

from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids
from claasp.components.or_component import OR
from claasp.components.and_component import AND
from claasp.components.xor_component import XOR
from claasp.components.not_component import NOT
from claasp.components.fsr_component import FSR
from claasp.components.sbox_component import SBOX
from claasp.components.shift_component import SHIFT
from claasp.components.sigma_component import Sigma
from claasp.components.rotate_component import Rotate
from claasp.components.modadd_component import MODADD
from claasp.components.modsub_component import MODSUB
from claasp.components.reverse_component import Reverse
from claasp.components.constant_component import Constant
from claasp.components.shift_rows_component import ShiftRows
from claasp.components.mix_column_component import MixColumn
from claasp.components.permutation_component import Permutation
from claasp.components.concatenate_component import Concatenate
from claasp.components.linear_layer_component import LinearLayer
from claasp.components.theta_xoodoo_component import ThetaXoodoo
from claasp.components.theta_keccak_component import ThetaKeccak
from claasp.components.cipher_output_component import CipherOutput
from claasp.components.variable_shift_component import VariableShift
from claasp.components.variable_rotate_component import VariableRotate
from claasp.components.word_permutation_component import WordPermutation
from claasp.components.intermediate_output_component import IntermediateOutput
from claasp.name_mappings import INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, CONSTANT, INPUT_KEY, LINEAR_LAYER, INPUT_PLAINTEXT

cipher_round_not_found_error = "Error! The cipher has no round: please run self.add_round() before adding any " \
                               "component. "


def add_AND_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create and add an and component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: and_0_0 = cipher.add_AND_component(["input","input"], [[0,1],[2,3]], 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = and_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input', 'input']
            input_bit_positions = [[0, 1], [2, 3]]
            output_bit_size = 2
            description = ['AND', 2]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = AND(cipher.current_round_number, cipher.current_round_number_of_components,
                        input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, new_component)
    return new_component


def add_cipher_output_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create and add a cipher output component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: component_0_0 = cipher.add_cipher_output_component(["input"], [[0,1,2,3]], 4)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = cipher_output_0_0
            type = cipher_output
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['cipher_output']
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = CipherOutput(cipher.current_round_number, cipher.current_round_number_of_components,
                                 input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, new_component)
    return new_component


def add_component(cipher, component):
    cipher.rounds.add_component(component)


def add_concatenate_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Add concatenate component to the current (last) round of the editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: concatenate_0_0 = cipher.add_concatenate_component(["input"], [[0,1,2,3]], 4)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = concatenate_0_0
            type = concatenate
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['', 0]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = Concatenate(cipher.current_round_number, cipher.current_round_number_of_components,
                                input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, new_component)
    return new_component


def add_constant_component(cipher, output_bit_size, value):
    """
    Use this function to create and add a constant component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``value`` -- **string**; the value of the constant

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [32], 32)
        sage: cipher.add_round()
        sage: constant_0_0 = cipher.add_constant_component(16, 0xAB01)
        sage: constant_0_1 = cipher.add_constant_component(16, 0xAB02)
        sage: cipher.print()
        cipher_id = cipher_name_i32_o32_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [32]
        cipher_output_bit_size = 32
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = constant_0_0
            type = constant
            input_bit_size = 0
            input_id_link = ['']
            input_bit_positions = [[]]
            output_bit_size = 16
            description = ['0xab01']
        <BLANKLINE>
            # round = 0 - round component = 1
            id = constant_0_1
            type = constant
            input_bit_size = 0
            input_id_link = ['']
            input_bit_positions = [[]]
            output_bit_size = 16
            description = ['0xab02']
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print("Error! The cipher has no rounds: please run self.add_round() before adding any component.")
        return None

    new_component = Constant(cipher.current_round_number, cipher.current_round_number_of_components,
                             output_bit_size, value)
    add_component(cipher, new_component)
    return new_component


def add_FSR_component(cipher, input_id_links, input_bit_positions, output_bit_size, description):
    """
    Use this function to create and add an lfsr/nlfsr component to editor.

    INPUT:
    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``description`` -- **[registers_info, integer, integer]**; registers_info are the information of the list of fsr
      registers, which is represented as [register_1_info, register_2_info, ..., register_n_info]. In each of the
      register information it contains [register_word_length, register_polynomial, clock_polynomial] where
      register_word_length is an integer that specifies the word length of the register. register_polynomial is the
      feedback polynomial of the register in fsr. For example, [[0],[1],[3],[2,5]] represents x0+x1+x3+x2*x5.
      clock_polynomial is the polynomial of register clock. If this field is not specified, by default, it will be
      performed always. For the polynomial with more than one bit in a word, the polynomial will be represented as
      coefficient and monomials. For example, [[2, [0]], [5, [1]], [15, [3]], [3,[2,5]]] with 4 bits in a word
      represents 0010*x0+0101*x1+1111*x3+0011*x2*x5. The second integer parameter determines how many bits inside a
      word. The third integer parameter determines how many clocks would be performed within this component. If this
      field is not specified, it would be always 1.
      For example, a description such as [[[5, [[4], [5], [6, 7]]],[7, [[0], [8], [1, 2]]]], 1] has two registers. The
      first one is [5, [[4], [5], [6, 7]], i.e. a register of length 5, its feedback polynomial is x4+x5+x6*x7.
      The second register is [7, [[0], [8], [1, 2]] of length 7, and its feedback polynomial is x0+x8+x1*x2.
      The last entry in the description list represents the word size which is 1-bit in this example.
      By default, the registers clock one time.

    EXAMPLES:

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "fsr", ["input"], [12], 12)
        sage: cipher.add_round()
        sage: fsr_0_0 = cipher.add_FSR_component(["input", "input"], [[0,1,2,3,4],[0,1,2,3,4,5,6]], 12, [[
        ....: [5, [[4], [5], [6, 7]]],  # Register_len:5,  feedback poly: x4 + x5 + x6*x7
        ....: [7, [[0], [8], [1, 2]]]  # Register_len:7, feedback poly: x0 + x1*x2 + x8
        ....: ], 1])
        sage: cipher.print()
        cipher_id = cipher_name_i12_o12_r1
        cipher_type = fsr
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [12]
        cipher_output_bit_size = 12
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = fsr_0_0
            type = fsr
            input_bit_size = 12
            input_id_link = ['input', 'input']
            input_bit_positions = [[0, 1, 2, 3, 4], [0, 1, 2, 3, 4, 5, 6]]
            output_bit_size = 12
            description = [[[5, [[4], [5], [6, 7]]], [7, [[0], [8], [1, 2]]]], 1]
        cipher_reference_code = None

    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = FSR(cipher.current_round_number, cipher.current_round_number_of_components,
                         input_id_links, input_bit_positions, output_bit_size, description)
    add_component(cipher, new_component)
    return new_component


def add_intermediate_output_component(cipher, input_id_links, input_bit_positions, output_bit_size, output_tag):
    """
    Use this function to create and add an intermediate output component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``output_tag`` -- **string**; tag to add to the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: component_0_0 = cipher.add_intermediate_output_component(["input"], [[0,1,2,3]], 4, "output_tag")
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = intermediate_output_0_0
            type = intermediate_output
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['output_tag']
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = IntermediateOutput(cipher.current_round_number, cipher.current_round_number_of_components,
                                       input_id_links, input_bit_positions, output_bit_size, output_tag)
    add_component(cipher, new_component)
    return new_component


def add_linear_layer_component(cipher, input_id_links, input_bit_positions, output_bit_size, description):
    """
    Use this function to create and add a linear layer component as a binary matrix to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``description`` -- **string**; the description of the linear layer

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: linear_layer_0_0 = cipher.add_linear_layer_component(
        ....: ["input"], [[0,1,2,3]], 4, [[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]])
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = linear_layer_0_0
            type = linear_layer
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = LinearLayer(cipher.current_round_number, cipher.current_round_number_of_components, input_id_links,
                                input_bit_positions, output_bit_size, description)
    add_component(cipher, new_component)
    return new_component


def add_mix_column_component(cipher, input_id_links, input_bit_positions, output_bit_size, mix_column_description):
    """
    Use this function to create a mixing column component in the editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``mix_column_description`` -- **string**; the description of the linear layer

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: mix_column_0_0 = cipher.add_mix_column_component(["input"], [[0,1,2,3]], 4, [[[2, 3], [3, 2]], 1, 3])
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = mix_column_0_0
            type = mix_column
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description =  [[[2, 3], [3, 2]], 1, 3]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = MixColumn(cipher.current_round_number, cipher.current_round_number_of_components, input_id_links,
                              input_bit_positions, output_bit_size, mix_column_description)
    add_component(cipher, new_component)
    return new_component


def add_MODADD_component(cipher, input_id_links, input_bit_positions, output_bit_size, modulus):
    """
    Use this function to create and add a modadd component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: modadd_0_0 = cipher.add_MODADD_component(["input","input"], [[0,1],[2,3]], 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = modadd_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input', 'input']
            input_bit_positions = [[0, 1], [2, 3]]
            output_bit_size = 2
            description = ['MODADD', 2, None]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = MODADD(cipher.current_round_number, cipher.current_round_number_of_components,
                           input_id_links, input_bit_positions, output_bit_size, modulus)
    add_component(cipher, new_component)
    return new_component


def add_MODSUB_component(cipher, input_id_links, input_bit_positions, output_bit_size, modulus):
    """
    Use this function to create a modsub component in the editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: modsub_0_0 = cipher.add_MODSUB_component(["input","input"], [[0,1],[2,3]], 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = modsub_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input', 'input']
            input_bit_positions = [[0, 1], [2, 3]]
            output_bit_size = 2
            description = ['MODSUB', 2, None]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = MODSUB(cipher.current_round_number, cipher.current_round_number_of_components,
                           input_id_links, input_bit_positions, output_bit_size, modulus)
    add_component(cipher, new_component)
    return new_component


def add_NOT_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create a not component in editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: not_0_0 = cipher.add_NOT_component(["input"], [[0,1,2,3]], 4)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = not_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['NOT', 0]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = NOT(cipher.current_round_number, cipher.current_round_number_of_components,
                        input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, new_component)
    return new_component


def add_OR_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create an or component in editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: or_0_0 = cipher.add_OR_component(["input","input"], [[0,1],[2,3]], 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = or_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input', 'input']
            input_bit_positions = [[0, 1], [2, 3]]
            output_bit_size = 2
            description = ['OR', 2]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = OR(cipher.current_round_number, cipher.current_round_number_of_components,
                       input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, new_component)
    return new_component


def add_permutation_component(cipher, input_id_links, input_bit_positions, output_bit_size,
                              permutation_description):
    """
    Create a permutation component to permute the bit position in the editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``permutation_description`` -- **string**; the description of the permutation

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: perm_0_0 = cipher.add_permutation_component(["input"], [[0,1,2,3]], 4, [3,2,1,0])
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = linear_layer_0_0
            type = linear_layer
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = [[0, 0, 0, 1], [0, 0, 1, 0], [0, 1, 0, 0], [1, 0, 0, 0]]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = Permutation(cipher.current_round_number, cipher.current_round_number_of_components,
                                input_id_links, input_bit_positions, output_bit_size, permutation_description)
    add_component(cipher, new_component)
    return new_component


def add_reverse_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Create and add a reverse component to reverse the bit position in editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: rev_0_0 = cipher.add_reverse_component(["input"], [[0,1,2,3]], 4)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = linear_layer_0_0
            type = linear_layer
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = [[0, 0, 0, 1], [0, 0, 1, 0], [0, 1, 0, 0], [1, 0, 0, 0]]
        cipher_reference_code = None
    """

    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = Reverse(cipher.current_round_number, cipher.current_round_number_of_components,
                            input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, new_component)
    return new_component


def add_rotate_component(cipher, input_id_links, input_bit_positions, output_bit_size, parameter):
    """
    Use this function to create and add a rotate component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``parameter`` -- **integer**; the number of bits to be rotated, positive for right rotation and negative for left
      rotation

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: rotate_0_0 = cipher.add_rotate_component(["input"], [[0,1,2,3]], 4, 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = rot_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['ROTATE', 2]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = Rotate(cipher.current_round_number, cipher.current_round_number_of_components,
                           input_id_links, input_bit_positions, output_bit_size, parameter)
    add_component(cipher, new_component)
    return new_component


def add_round(cipher):
    """
    Use this function to add a new empty round to the cipher.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: cipher.print_as_python_dictionary()
        cipher = {
        'cipher_id': 'cipher_name_i4_o4_r1',
        'cipher_type': 'permutation',
        'cipher_inputs': ['input'],
        'cipher_inputs_bit_size': [4],
        'cipher_output_bit_size': 4,
        'cipher_number_of_rounds': 1,
        'cipher_rounds' : [
          # round 0
          [
          ],
          ],
        'cipher_reference_code': None,
        }
    """
    cipher.rounds.add_round()
    cipher.set_id(make_cipher_id(cipher.family_name, cipher.inputs, cipher.inputs_bit_size,
                                 cipher.output_bit_size, cipher.number_of_rounds))
    cipher.set_file_name(make_file_name(cipher.id))


def add_round_key_output_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create a round key output component in editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: component_0_0 = cipher.add_round_key_output_component(["input"], [[0,1,2,3]], 4)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = intermediate_output_0_0
            type = intermediate_output
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['round_key_output']
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = IntermediateOutput(cipher.current_round_number, cipher.current_round_number_of_components,
                                       input_id_links, input_bit_positions, output_bit_size, 'round_key_output')
    add_component(cipher, new_component)
    return new_component


def add_round_output_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create and add a round output component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: component_0_0 = cipher.add_round_output_component(["input"], [[0,1,2,3]], 4)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = intermediate_output_0_0
            type = intermediate_output
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['round_output']
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = IntermediateOutput(cipher.current_round_number, cipher.current_round_number_of_components,
                                       input_id_links, input_bit_positions, output_bit_size, 'round_output')
    add_component(cipher, new_component)
    return new_component


def add_SBOX_component(cipher, input_id_links, input_bit_positions, output_bit_size, description):
    """
    Use this function to create and add a sbox component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``description`` -- **string**; the description of the sbox

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: sbox_0_0 = cipher.add_SBOX_component(["input"], [[0,1,2,3]], 4,
        ....: [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = sbox_0_0
            type = sbox
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = SBOX(cipher.current_round_number, cipher.current_round_number_of_components,
                         input_id_links, input_bit_positions, output_bit_size, description)
    add_component(cipher, new_component)
    return new_component


def add_SHIFT_component(cipher, input_id_links, input_bit_positions, output_bit_size, parameter):
    """
    Use this function to create and add a shift component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``parameter`` -- **integer**; the number of bits to be shifted, positive for right shift and negative for left
      shift

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: shift_0_0 = cipher.add_SHIFT_component(["input"], [[0,1,2,3]], 4, 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = shift_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['SHIFT', 2]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = SHIFT(cipher.current_round_number, cipher.current_round_number_of_components,
                          input_id_links, input_bit_positions, output_bit_size, parameter)
    add_component(cipher, new_component)
    return new_component


def add_shift_rows_component(cipher, input_id_links, input_bit_positions, output_bit_size, parameter):
    """
    Use this function to create rotate component in editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``parameter`` -- **integer**; the number of word to be shifted, positive for right rotation and negative for left
      rotation

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: shift_row_0_0 = cipher.add_shift_rows_component(["input"], [[0,1,2,3]], 4, 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = shift_rows_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = ['ROTATE', 2]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = ShiftRows(cipher.current_round_number, cipher.current_round_number_of_components,
                              input_id_links, input_bit_positions, output_bit_size, parameter)
    add_component(cipher, new_component)
    return new_component


def add_sigma_component(cipher, input_id_links, input_bit_positions, output_bit_size, rotation_amounts_parameter):
    """
    Use this function to create a sigma component in cipher.

    .. NOTE::

        See :py:class:`Ascon Permutation <ciphers.permutations.ascon_permutation>`.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``rotation_amounts_parameter`` -- **list**; the direction of the rotation, positive for right rotation
      and negative for left rotation

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: sigma_0_0 = cipher.add_sigma_component(["input"], [[0,1,2,3]], 4, [1,3])
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = sigma_0_0
            type = linear_layer
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = [(1, 1, 0, 1), (1, 1, 1, 0), (0, 1, 1, 1), (1, 0, 1, 1)]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    linear_layer_component = Sigma(cipher.current_round_number, cipher.current_round_number_of_components,
                                   input_id_links, input_bit_positions,
                                   output_bit_size, rotation_amounts_parameter)
    add_component(cipher, linear_layer_component)
    return linear_layer_component


def add_theta_keccak_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create the theta component of Keccak in cipher.

    .. NOTE::

        See Keccak linear layer.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [1600], 1600)
        sage: cipher.add_round()
        sage: input_bit_positions = [[i for i in range(1600)]]
        sage: theta_keccak_0_0 = cipher.add_theta_keccak_component(["input"], input_bit_positions, 1600)
        sage: theta_keccak_0_0.type
        'linear_layer'
    """
    if cipher.number_of_rounds == 0:
        print(cipher_round_not_found_error)
        return None

    new_component = ThetaKeccak(cipher.current_round_number, cipher.current_round_number_of_components,
                                input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, new_component)
    return new_component


def add_theta_xoodoo_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create the theta component of Xoodoo in cipher.

    .. NOTE::

        See Xoodoo linear layer.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [384], 384)
        sage: cipher.add_round()
        sage: input_bit_positions = [[i for i in range(384)]]
        sage: theta_xoodoo_0_0 = cipher.add_theta_xoodoo_component(["input"], input_bit_positions, 384)
        sage: theta_xoodoo_0_0.type
        'linear_layer'
    """
    if cipher.number_of_rounds == 0:
        print(cipher_round_not_found_error)
        return None

    theta_xoodoo_component = ThetaXoodoo(cipher.current_round_number, cipher.current_round_number_of_components,
                                         input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, theta_xoodoo_component)
    return deepcopy(theta_xoodoo_component)


def add_variable_rotate_component(cipher, input_id_links, input_bit_positions, output_bit_size, parameter):
    """
    Use this function to create a variable rotate component in editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``parameter`` -- **list**; the direction of the rotation, positive for right rotation and negative for left
      rotation

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: var_rotate_0_0 = cipher.add_variable_rotate_component(["input", "input"], [[0, 1, 2, 3],
        ....: [4, 5, 6, 7]], 4, -1)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = var_rot_0_0
            type = word_operation
            input_bit_size = 8
            input_id_link = ['input', 'input']
            input_bit_positions = [[0, 1, 2, 3], [4, 5, 6, 7]]
            output_bit_size = 4
            description = ['ROTATE_BY_VARIABLE_AMOUNT', -1]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = VariableRotate(cipher.current_round_number, cipher.current_round_number_of_components,
                                   input_id_links, input_bit_positions, output_bit_size, parameter)
    add_component(cipher, new_component)
    return new_component


def add_variable_shift_component(cipher, input_id_links, input_bit_positions, output_bit_size, parameter):
    """
    Use this function to create a variable shift component in editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``parameter`` -- **integer**; the direction of the shift, positive for right shift and negative for left shift

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: var_shift_0_0 = cipher.add_variable_shift_component(["input", "input"], [[0,1,2,3], [4,5,6,7]], 4, -1)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = var_shift_0_0
            type = word_operation
            input_bit_size = 8
            input_id_link = ['input', 'input']
            input_bit_positions = [[0, 1, 2, 3], [4, 5, 6, 7]]
            output_bit_size = 4
            description = ['SHIFT_BY_VARIABLE_AMOUNT', -1]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = VariableShift(cipher.current_round_number, cipher.current_round_number_of_components,
                                  input_id_links, input_bit_positions, output_bit_size, parameter)
    add_component(cipher, new_component)
    return new_component


def add_word_permutation_component(cipher, input_id_links, input_bit_positions, output_bit_size,
                                   permutation_description, word_size):
    """
    Create a permutation component to permute the word position in the editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component
    - ``permutation_description`` -- **list**; the description of the permutation (word_based)
    - ``word_size`` -- **integer**; define the size of each word

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: perm_0_0 = cipher.add_word_permutation_component(["input"], [[0,1,2,3]], 4, [1,0], 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = mix_column_0_0
            type = mix_column
            input_bit_size = 4
            input_id_link = ['input']
            input_bit_positions = [[0, 1, 2, 3]]
            output_bit_size = 4
            description = [[[0, 1], [1, 0]], 0, 2]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = WordPermutation(cipher.current_round_number, cipher.current_round_number_of_components,
                                    input_id_links, input_bit_positions,
                                    output_bit_size, permutation_description, word_size)
    add_component(cipher, new_component)
    return new_component


def add_XOR_component(cipher, input_id_links, input_bit_positions, output_bit_size):
    """
    Use this function to create and add a xor component to editor.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher
    - ``input_id_links`` -- **list**; the list of input_id links
    - ``input_bit_positions`` -- **list**; the list of input_bits corresponding to the input_id links
    - ``output_bit_size`` -- **integer**; the output bits of the component

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: xor_0_0 = cipher.add_XOR_component(["input","input"], [[0,1],[2,3]], 2)
        sage: cipher.print()
        cipher_id = cipher_name_i4_o4_r1
        cipher_type = permutation
        cipher_inputs = ['input']
        cipher_inputs_bit_size = [4]
        cipher_output_bit_size = 4
        cipher_number_of_rounds = 1
        <BLANKLINE>
            # round = 0 - round component = 0
            id = xor_0_0
            type = word_operation
            input_bit_size = 4
            input_id_link = ['input', 'input']
            input_bit_positions = [[0, 1], [2, 3]]
            output_bit_size = 2
            description = ['XOR', 2]
        cipher_reference_code = None
    """
    if cipher.current_round_number is None:
        print(cipher_round_not_found_error)
        return None

    new_component = XOR(cipher.current_round_number, cipher.current_round_number_of_components,
                        input_id_links, input_bit_positions, output_bit_size)
    add_component(cipher, new_component)
    return new_component


def generate_expanded_links(component, input_bit_positions):
    expanded_links = []
    for link, positions in zip(component.input_id_links, input_bit_positions):
        expanded_links.extend([link] * len(positions))

    return expanded_links


def get_final_input_positions(new_input_positions, unique_lengths):
    final_input_positions = []
    start = 0
    end = 0
    for unique_length in unique_lengths:
        end += unique_length
        final_input_positions.append(new_input_positions[start:end])
        start += unique_length

    return final_input_positions


def get_unique_links_information(new_links):
    unique_links = []
    unique_lengths = [0]
    current_link = new_links[0]
    current_length = 0
    for link in new_links:
        if link == current_link:
            current_length += 1
        else:
            unique_links.append(current_link)
            unique_lengths.append(current_length)
            current_link = link
            current_length = 1
    unique_links.append(current_link)
    unique_lengths.append(current_length)

    return unique_lengths, unique_links


def is_linear_layer_permutation(M, M_T):
    ones = [1] * len(M)
    M_has_only_one_1_in_rows = ([sum(row) for row in M] == ones)
    M_has_only_one_1_in_cols = ([sum(row) for row in M_T] == ones)

    return M_has_only_one_1_in_rows and M_has_only_one_1_in_cols


def make_cipher_id(family_name, inputs, inputs_bit_size,
                   output_bit_size, number_of_rounds):
    cipher_id = f'{family_name}'
    for i in range(len(inputs)):
        cipher_id += f'_{inputs[i][0]}{inputs_bit_size[i]}'

    cipher_id += f'_o{output_bit_size}_r{number_of_rounds}'
    return cipher_id


def make_file_name(cipher_id):
    return f'{cipher_id}.py'


def next_component_index_from(index):
    return index + 1


def propagate_equivalences(cipher, round_id, component_id, new_expanded_links, new_positions):
    for round_ in cipher._rounds.rounds[round_id:]:
        for component in round_.components:
            while component_id in component.input_id_links:
                input_id_link = component.input_id_links
                id_index = input_id_link.index(component_id)
                old_positions = component.input_bit_positions[id_index]
                new_links = [new_expanded_links[i] for i in old_positions]
                new_input_positions = [new_positions[i] for i in old_positions]
                unique_lengths, unique_links = get_unique_links_information(new_links)
                final_input_positions = get_final_input_positions(new_input_positions, unique_lengths)
                input_id_links = input_id_link[:id_index] + unique_links \
                                 + input_id_link[id_index + 1:]
                component.set_input_id_links(input_id_links)
                input_bit_positions = component.input_bit_positions
                component.set_input_bit_positions(input_bit_positions[:id_index] \
                                                  + final_input_positions \
                                                  + input_bit_positions[id_index + 1:])
                while [] in component.input_bit_positions:
                    component.input_bit_positions.remove([])


def propagate_permutations(cipher):
    cipher_without_permutations = deepcopy(cipher)
    ids_of_permutations = []
    for round_ in cipher_without_permutations.rounds_as_list:
        for component in round_.components:
            if component.type == LINEAR_LAYER:
                M = component.description
                number_of_rows = len(M)
                number_of_columns = len(M[0])
                M_is_square = (number_of_rows == number_of_columns)
                if M_is_square:
                    M_T = [[M[i][j] for i in range(number_of_rows)] for j in range(number_of_columns)]
                    if is_linear_layer_permutation(M, M_T):
                        ids_of_permutations.append(component.id)
                        input_bit_positions = component.input_bit_positions
                        expanded_links = generate_expanded_links(component, input_bit_positions)
                        flat_input_bit_positions = [position for positions in input_bit_positions
                                                    for position in positions]
                        new_expanded_links = [expanded_links[row.index(1)] for row in M_T]
                        new_positions = [flat_input_bit_positions[row.index(1)] for row in M_T]
                        propagate_equivalences(cipher_without_permutations, round_.id, component.id,
                                               new_expanded_links, new_positions)
    return (ids_of_permutations, cipher_without_permutations)


def propagate_rotations(cipher):
    cipher_without_rotations = deepcopy(cipher)
    for round_ in cipher_without_rotations.rounds_as_list:
        for component in round_.components:
            if component.description[0] == 'ROTATE':
                input_bit_positions = component.input_bit_positions
                expanded_links = []
                for link, positions in zip(component.input_id_links, input_bit_positions):
                    expanded_links.extend([link] * len(positions))
                flat_input_bit_positions = [position for positions in input_bit_positions
                                            for position in positions]
                amount = component.description[1]
                new_expanded_links = expanded_links[-amount:] + expanded_links[:-amount]
                new_positions = flat_input_bit_positions[-amount:] + flat_input_bit_positions[:-amount]
                propagate_equivalences(cipher_without_rotations, round_.id, component.id,
                                       new_expanded_links, new_positions)
    return cipher_without_rotations


def remove_cipher_input_keys(cipher):
    cipher_without_key_schedule = deepcopy(cipher)
    if INPUT_KEY in cipher_without_key_schedule.inputs:
        key_index = cipher_without_key_schedule.inputs.index(INPUT_KEY)
        cipher_without_key_schedule.inputs.pop(key_index)
        cipher_without_key_schedule.inputs_bit_size.pop(key_index)
    return cipher_without_key_schedule


def remove_forbidden_parents(rounds, cipher_without_key_schedule):
    forbidden_parents = {INPUT_KEY, CONSTANT}
    for cipher_round in rounds:
        for component in cipher_round.components:
            input_id_links = set(component.input_id_links)
            allowed_inputs = input_id_links - forbidden_parents
            other_links = list(filter(lambda link: CONSTANT in link, allowed_inputs))
            if (not allowed_inputs) or (len(other_links) == len(allowed_inputs)):
                forbidden_parents.add(component.id)
                cipher_without_key_schedule.remove_round_component_from_id(cipher_round.id, component.id)


def remove_key_schedule(cipher):
    """
    Return a dictionary. A key is an output bit of a component.

    A value is a list of input bits which are the end point of an arc in Cipher for the relative key.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: speck = SpeckBlockCipher(number_of_rounds=4)
        sage: removed_key_speck = speck.remove_key_schedule()
        sage: removed_key_speck.print_as_python_dictionary()
        cipher = {
        ...
        'cipher_rounds' : [
          # round 0
          ...
          # round 1
          [
          {
            # round = 1 - round component = 0
            'id': 'rot_1_6',
            'type': 'word_operation',
            'input_bit_size': 16,
            'input_id_link': ['xor_0_2'],
            'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
            'output_bit_size': 16,
            'description': ['ROTATE', 7],
          },
          ...
          ],
          # round 2
          ...
          # round 3
          ...
          ],
        'cipher_reference_code': None,
        }
    """
    cipher_without_key_schedule = remove_cipher_input_keys(cipher)
    remove_forbidden_parents(cipher.rounds_as_list, cipher_without_key_schedule)
    remove_orphan_components(cipher_without_key_schedule)
    update_inputs(cipher_without_key_schedule)

    return cipher_without_key_schedule


def remove_orphan_components(cipher_without_key_schedule):
    links_or_types_to_save = {INTERMEDIATE_OUTPUT, CIPHER_OUTPUT}
    for cipher_round in reversed(cipher_without_key_schedule.rounds_as_list):
        for component in reversed(cipher_round.components):
            links_or_types_to_save.update(component.input_id_links)
            if (component.id not in links_or_types_to_save) and (component.type not in links_or_types_to_save):
                cipher_without_key_schedule.remove_round_component(cipher_round.id, component)


def remove_permutations(cipher):
    """
    Remove rotation components from the cipher instance keeping its effect.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
        sage: from claasp.editor import remove_permutations
        sage: present = PresentBlockCipher(number_of_rounds=5)
        sage: removed_permutations_present = remove_permutations(present)
        sage: removed_permutations_present.print_as_python_dictionary()
        cipher = {
        ...
        'cipher_rounds' : [
          ...
          {
            # round = 0 - round component = 16
            'id': 'sbox_0_16',
            'type': 'sbox',
            'input_bit_size': 4,
            'input_id_link': ['xor_0_0'],
            'input_bit_positions': [[60, 61, 62, 63]],
            'output_bit_size': 4,
            'description': [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2],
          },
          {
            # round = 0 - round component = 17
            'id': 'rot_0_18',
            'type': 'word_operation',
            'input_bit_size': 80,
            'input_id_link': ['key'],
            'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79]],
            'output_bit_size': 80,
            'description': ['ROTATE', -61],
          },
          {
            # round = 0 - round component = 18
            'id': 'sbox_0_19',
            'type': 'sbox',
            'input_bit_size': 4,
            'input_id_link': ['rot_0_18'],
            'input_bit_positions': [[0, 1, 2, 3]],
            'output_bit_size': 4,
            'description': [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2],
          },
          ...
            return int_to_bytearray(state, 64)
        ''',
        }
    """
    (ids_of_permutations, cipher_without_permutations) = propagate_permutations(cipher)
    for round_ in cipher.rounds_as_list:
        for component in round_.components:
            if component.id in ids_of_permutations:
                cipher_without_permutations.remove_round_component_from_id(round_.id, component.id)
    return cipher_without_permutations


def remove_rotations(cipher):
    """
    Remove rotation components from the cipher instance keeping its effect.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.editor import remove_rotations
        sage: speck = SpeckBlockCipher(number_of_rounds=5)
        sage: removed_rotations_speck = remove_rotations(speck)
        sage: removed_rotations_speck.print_as_python_dictionary()
        cipher = {
        'cipher_id': 'speck_p32_k64_o32_r5',
        'cipher_type': 'block_cipher',
        'cipher_inputs': ['plaintext', 'key'],
        'cipher_inputs_bit_size': [32, 64],
        'cipher_output_bit_size': 32,
        'cipher_number_of_rounds': 5,
        'cipher_rounds' : [
          # round 0
          [
          {
            # round = 0 - round component = 0
            'id': 'modadd_0_1',
            'type': 'word_operation',
            'input_bit_size': 32,
            'input_id_link': ['plaintext', 'plaintext'],
            'input_bit_positions': [[9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8], [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
            'output_bit_size': 16,
            'description': ['MODADD', 2, None],
          },
          ...
          ],
          # round 1
          [
          {
            # round = 1 - round component = 0
            'id': 'constant_1_0',
            'type': 'constant',
            'input_bit_size': 0,
            'input_id_link': [''],
            'input_bit_positions': [[]],
            'output_bit_size': 16,
            'description': ['0x0000'],
          },
          ...
          ],
          # round 2
          [
          {
            # round = 2 - round component = 0
            'id': 'constant_2_0',
            'type': 'constant',
            'input_bit_size': 0,
            'input_id_link': [''],
            'input_bit_positions': [[]],
            'output_bit_size': 16,
            'description': ['0x0001'],
          },
          ...
          ],
          # round 3
          [
          {
            # round = 3 - round component = 0
            'id': 'constant_3_0',
            'type': 'constant',
            'input_bit_size': 0,
            'input_id_link': [''],
            'input_bit_positions': [[]],
            'output_bit_size': 16,
            'description': ['0x0002'],
          },
          ...
          ],
          # round 4
          [
          {
            # round = 4 - round component = 0
            'id': 'constant_4_0',
            'type': 'constant',
            'input_bit_size': 0,
            'input_id_link': [''],
            'input_bit_positions': [[]],
            'output_bit_size': 16,
            'description': ['0x0003'],
          },
          ...
          ],
          ],
        'cipher_reference_code': None,
        }

    """
    cipher_without_rotations = propagate_rotations(cipher)
    for round_ in cipher.rounds_as_list:
        for component in round_.components:
            if component.description[0] == 'ROTATE':
                cipher_without_rotations.remove_round_component_from_id(round_.id, component.id)
    return cipher_without_rotations


def remove_round_component(cipher, round_id, component):
    cipher.rounds.remove_round_component(round_id, component)


def remove_round_component_from_id(cipher, round_id, component_id):
    cipher.rounds.remove_round_component_from_id(round_id, component_id)

def get_key_schedule(cipher):
    """
        Return the key schedule, if any, as a Cipher object.

        INPUT:

        - ``cipher`` -- **Cipher object**; an instance of the object cipher

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: speck_key_schedule = speck.get_key_schedule()
            sage: speck_key_schedule.print_as_python_dictionary()
            cipher = {
            ...
            'cipher_rounds' : [
              # round 0
              ...
              # round 1
              [
              {
                # round = 1 - round component = 0
                'id': 'constant_1_0',
                'type': 'constant',
                'input_bit_size': 0,
                'input_id_link': [''],
                'input_bit_positions': [[]],
                'output_bit_size': 16,
                'description': ['0x0000'],
              },
              ...
              ],
              # round 2
              ...
              # round 3
              ...
              ],
            'cipher_reference_code': None,
            }
        """

    if INPUT_KEY not in cipher.inputs:
        raise Exception("The primitive does not have a key schedule.")

    graph_cipher = create_networkx_graph_from_input_ids(cipher)
    key_schedule_component_ids = set(nx.dfs_tree(graph_cipher, source=INPUT_KEY)) - set(nx.dfs_tree(graph_cipher, source=INPUT_PLAINTEXT))
    constants_ids = set(chain.from_iterable(graph_cipher.predecessors(i) for i in key_schedule_component_ids))

    cipher_with_only_key_schedule = deepcopy(cipher)
    for input in set(cipher_with_only_key_schedule.inputs) - {INPUT_KEY}:
        index = cipher_with_only_key_schedule.inputs.index(input)
        cipher_with_only_key_schedule.inputs.pop(index)
        cipher_with_only_key_schedule.inputs_bit_size.pop(index)

    for cipher_round in cipher.rounds_as_list:
        for component in cipher_round.components:
            if component.id not in key_schedule_component_ids.union(constants_ids):
                cipher_with_only_key_schedule .remove_round_component_from_id(cipher_round.id, component.id)

    return cipher_with_only_key_schedule

def sort_cipher(cipher):
    """
    Sort the cipher in a way that each component input is defined before the current component.

    INPUT:

    - ``cipher`` -- **Cipher object**; an instance of the object cipher

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
        sage: cipher.add_round()
        sage: sbox_that_should_be_second = cipher.add_SBOX_component(["sbox_0_1"], [[0,1,2,3]], 4,
        ....: [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
        sage: sbox_that_should_be_first = cipher.add_SBOX_component(["input"], [[0,1,2,3]], 4,
        ....: [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
        sage: cipher.print_as_python_dictionary()
        cipher = {
        'cipher_id': 'cipher_name_i4_o4_r1',
        'cipher_type': 'permutation',
        'cipher_inputs': ['input'],
        'cipher_inputs_bit_size': [4],
        'cipher_output_bit_size': 4,
        'cipher_number_of_rounds': 1,
        'cipher_rounds' : [
        # round 0
        [
        {
            # round = 0 - round component = 0
            'id': 'sbox_0_0',
            'type': 'sbox',
            'input_bit_size': 4,
            'input_id_link': ['sbox_0_1'],
            'input_bit_positions': [[0, 1, 2, 3]],
            'output_bit_size': 4,
            'description': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        },
        {
            # round = 0 - round component = 1
            'id': 'sbox_0_1',
            'type': 'sbox',
            'input_bit_size': 4,
            'input_id_link': ['input'],
            'input_bit_positions': [[0, 1, 2, 3]],
            'output_bit_size': 4,
            'description': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        },
        ],
        ],
        'cipher_reference_code': None,
        }

        sage: cipher.sort_cipher()
        sage: cipher.print_as_python_dictionary()
        cipher = {
        'cipher_id': 'cipher_name_i4_o4_r1',
        'cipher_type': 'permutation',
        'cipher_inputs': ['input'],
        'cipher_inputs_bit_size': [4],
        'cipher_output_bit_size': 4,
        'cipher_number_of_rounds': 1,
        'cipher_rounds' : [
        # round 0
        [
        {
            # round = 0 - round component = 0
            'id': 'sbox_0_1',
            'type': 'sbox',
            'input_bit_size': 4,
            'input_id_link': ['input'],
            'input_bit_positions': [[0, 1, 2, 3]],
            'output_bit_size': 4,
            'description': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        },
        {
            # round = 0 - round component = 1
            'id': 'sbox_0_0',
            'type': 'sbox',
            'input_bit_size': 4,
            'input_id_link': ['sbox_0_1'],
            'input_bit_positions': [[0, 1, 2, 3]],
            'output_bit_size': 4,
            'description': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        },
        ],
        ],
        'cipher_reference_code': None,
        }
    """
    for i in range(cipher.number_of_rounds):
        current_round = cipher.rounds.round_at(i)
        for fixed_index in range(current_round.get_number_of_components()):
            for moving_index in range(next_component_index_from(fixed_index),
                                      current_round.number_of_components):
                if current_round.is_component_input(fixed_index, moving_index):
                    current_round.swap_components(fixed_index, moving_index)


def update_cipher_inputs(cipher_without_key_schedule, component_id, modified, offset):
    if modified:
        cipher_without_key_schedule.inputs.append(component_id)
        cipher_without_key_schedule.inputs_bit_size.append(offset)


def update_component_inputs(component, component_id, parent_links):
    offset = 0
    modified = False
    parent_links.add(component.id)
    input_id_links = component.input_id_links
    for i in range(len(input_id_links)):
        if input_id_links[i] not in parent_links and input_id_links[i] != '':
            input_id_links[i] = component_id
            bit_len = len(component.input_bit_positions[i])
            component.input_bit_positions[i] = list(range(offset, bit_len + offset))
            offset += bit_len
            modified = True
    return modified, offset


def update_inputs(cipher_without_key_schedule):
    parent_links = set(cipher_without_key_schedule.inputs)
    for cipher_round in cipher_without_key_schedule.rounds_as_list:
        for index, component in enumerate(cipher_round.components):
            component_id = f'key_{cipher_round.id}_{index}'
            modified, offset = update_component_inputs(component, component_id, parent_links)
            update_cipher_inputs(cipher_without_key_schedule, component_id, modified, offset)

def get_output_bit_size_from_id(cipher_list, component_id):
    try:
        for cipher in cipher_list:
            if component_id in cipher.inputs:
                return cipher.inputs_bit_size[cipher.inputs.index(component_id)]
            elif component_id in cipher.get_all_components_ids():
                return cipher.get_component_from_id(component_id).output_bit_size
        raise ValueError(f'{component_id} not found.')
    except ValueError as e:
        sys.exit(str(e))


