
# ****************************************************************************
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


import copy
import math
import numpy as np
from numpy.linalg import multi_dot
from decimal import Decimal, getcontext, MAX_EMAX

from sage.crypto.sbox import SBox
from sage.rings.quotient_ring import QuotientRing
from sage.rings.finite_rings.finite_field_constructor import FiniteField
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing

from claasp.utils.utils import int_to_poly, poly_to_int

getcontext().Emax = MAX_EMAX


def AND_continuous_diffusion_analysis(input_lst, number_of_inputs):
    """
    Compute the continuous generalization of the and operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    """
    block_len = len(input_lst) // number_of_inputs
    x = input_lst[0:block_len]
    y = input_lst[block_len:2 * block_len]
    output = [0.0] * block_len
    for j in range(block_len):
        output[j] = extended_and_bit(x[j], y[j])

    return output


def CONSTANT_continuous_diffusion_analysis(input_lst, number_of_outputs):
    """

    Compute the continuous generalization of a constant operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``number_of_inputs`` -- **integer**; specify the number of elements of the input
    """
    format_size = '{:0' + str(number_of_outputs) + 'b}'
    input_str = format_size.format(input_lst)
    input_lst_max_bias = []
    for i_bit in input_str:
        if i_bit == '0':
            input_lst_max_bias.append(Decimal(-1))
        else:
            input_lst_max_bias.append(Decimal(1))

    return input_lst_max_bias


def LINEAR_LAYER_continuous_diffusion_analysis(input_lst, linear_matrix):
    """
    Compute the continuous generalization of a linear_layer operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``linear_matrix`` -- **list**; list of lists containing the matrix representation of the linear operation
    """
    def XOR_bit(x, y):
        return Decimal(-1.0) * x * y

    output_vector = [Decimal(float(0.0)) for _ in range(len(input_lst))]
    for i in range(len(linear_matrix)):

        if linear_matrix[i][0] == 0:
            Tm = Decimal(-1)
        else:
            Tm = Decimal(float(input_lst[0]))
        for j in range(1, len(linear_matrix[0])):
            if linear_matrix[i][j] == 0:
                Tm1 = Decimal(-1)
            else:
                Tm1 = Decimal(float(input_lst[j]))
            Tm = XOR_bit(Tm, Tm1)
        output_vector[i] = Tm

    return output_vector


def MODADD_continuous_diffusion_analysis(input_lst, number_of_inputs):
    """
    Compute the continuous generalization of a (or more) modular addition operation(s) [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    """
    block_len = len(input_lst) // number_of_inputs
    x = input_lst[0:block_len]
    y = input_lst[block_len:2 * block_len]
    z = MODADD_continuous_diffusion_analysis_two_words(x + y)
    for j in range(number_of_inputs - 2):
        z = MODADD_continuous_diffusion_analysis_two_words(
            z + input_lst[(j + 2) * block_len:(j + 2) * block_len + block_len]
        )

    return z


def MODADD_continuous_diffusion_analysis_two_words(input_lst):
    """
    Compute the continuous generalization of a modular addition component [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    """
    number_of_inputs = 2

    def XOR_bit(x_input, y_input):
        return Decimal(-1.0) * x_input * y_input

    def MAJ(x_input, y_input, z):
        return Decimal(0.5) * (x_input + y_input + z - x_input * y_input * z)

    block_len = len(input_lst) // number_of_inputs
    x = input_lst[0:block_len]
    y = input_lst[block_len:2 * block_len]
    output = [0.0] * block_len
    c = [0.0] * (block_len + 1)
    c[0] = Decimal(-1.0)
    for i in range(0, block_len):
        output[i] = XOR_bit(XOR_bit(x[i], y[i]), c[i])
        c[i + 1] = MAJ(x[i], y[i], c[i])

    return output


def MODSUB_continuous_diffusion_analysis(input_lst, number_of_inputs):
    """
    Compute the continuous generalization of a (or more) modular substraction operation (s) [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    """
    return MODADD_continuous_diffusion_analysis(input_lst, number_of_inputs)


def NOT_continuous_diffusion_analysis(input_lst):
    """
    Compute the continuous generalization of the not operation [MUR2020]_.

    INPUT:

    - ``input_lst`` --  **list**; is a list of real numbers in the range [-1, 1]
    """
    block_len = len(input_lst)
    output = [0.0 for _ in range(block_len)]
    for j in range(block_len):
        output[j] = extended_not_bit(input_lst[j])

    return output


def OR_continuous_diffusion_analysis(input_lst, number_of_inputs):
    """
    Compute the continuous generalization of the or operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    """
    block_len = len(input_lst) // number_of_inputs
    x = input_lst[0:block_len]
    y = input_lst[block_len:2 * block_len]
    output = [0.0] * block_len
    for j in range(block_len):
        output[j] = (-1 * x[j] * y[j] + x[j] + y[j] + 1) / 2

    return output


def ROTATE_continuous_diffusion_analysis(input_lst, rotation_amount):
    """
    Compute the continuous generalization of the rotate operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; a float list
    - ``rotation_amount`` -- **integer**; an integer indicating the amount of the rotation, positive for right rotation,
      negative for left rotation
    """
    length_input = len(input_lst)
    r = rotation_amount % length_input
    output = copy.deepcopy(input_lst)
    for i in range(length_input - r):
        output[i + r] = input_lst[i]
    for i in range(r):
        output[i] = input_lst[length_input - r + i]

    return output


def ROTATE_BY_VARIABLE_AMOUNT_continuous_diffusion_analysis(input_lst, input_size, rotation_direction):
    """
    INPUT:

    - ``input_lst`` -- **list**; a list representing a list of real numbers
    - ``input_size`` -- **integer**; size of the float list to be rotated
    - ``rotation_direction`` -- **integer**; indicates the direction of the rotation, positive for right and negative
      for left
    """
    input_lst = input_lst[:input_size]
    rotation_amount_lst = input_lst[input_size:]
    rotation_amount_lst = rotation_amount_lst[::-1]

    input_lst_len = len(input_lst)
    rotation_amount_lst_len = len(rotation_amount_lst)
    format_rotation_amount_lst_len = '{:0' + str(rotation_amount_lst_len) + 'b}'
    binary_rotation_amount_lst_len = int(format_rotation_amount_lst_len.format(input_lst_len))
    binary_list_rotation_amount_lst_len = [int(d) for d in str(bin(binary_rotation_amount_lst_len))[2:]]
    rotation_amount_lst = AND_continuous_diffusion_analysis(
        rotation_amount_lst + binary_list_rotation_amount_lst_len[::-1], 2
    )

    if rotation_direction < 0:
        return extended_left_rotation_by_variable_amount(
            input_lst, rotation_amount_lst
        )
    else:
        return extended_right_rotation_by_variable_amount(
            input_lst, rotation_amount_lst
        )


def SBOX_continuous_diffusion_analysis(input_lst, sbox_precomputations):
    """
    Compute the continuous generalization of a sbox operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``sbox_precomputations`` -- **dictionary**; is a dictionary containing precomputations for the sbox

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions_continuous_diffusion_analysis import *
        sage: lookup_table = [ 0,1,5,4,4,7,5,6 ]
        sage: input_lst = [Decimal(float(0.1)), Decimal(float(0.1)), Decimal(float(0.1))]
        sage: evaluated_y_list, minus1_power_x_s = compute_sbox_precomputations(lookup_table)
        sage: sbox_precomputations = {}
        sage: sbox_precomputations["evaluated_boolean_function"] = evaluated_y_list
        sage: sbox_precomputations["minus1_power_x_t"] = minus1_power_x_s
        sage: sbox_precomputations["lookup_table"] = lookup_table
        sage: output_lst = [
        ....:     Decimal('-0.0100000000000000011102230245'),
        ....:     Decimal('-0.3949999999999999938937733645'),
        ....:     Decimal('0.595000000000000004996003611')
        ....: ]
        sage: SBOX_continuous_diffusion_analysis(input_lst, sbox_precomputations) == output_lst
        True
    """
    lookup_table = sbox_precomputations["lookup_table"]
    dim = math.log(len(lookup_table), 2)

    evaluated_boolean_function = sbox_precomputations["evaluated_boolean_function"]
    minus1_power_x_t = sbox_precomputations["minus1_power_x_t"]

    input_lst = np.array(input_lst).transpose()
    output_lst = _compute_continuous_function_for_sbox_component(dim, evaluated_boolean_function,
                                                                 input_lst, minus1_power_x_t)
    output_lst = [Decimal(output_lst[i]) for i in range(len(output_lst))]

    return output_lst


def SHIFT_continuous_diffusion_analysis(input_lst, shift_amount):
    """
    Compute the continuous generalization of the shit operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; a BitArray representing a binary string
    - ``shift_amount`` -- **integer**; an integer indicating the amount of the shift, positive for right shift,
      negative for left shift
    """
    length_input = len(input_lst)
    output = [Decimal(1) for _ in range(length_input)]
    if shift_amount >= length_input:
        return output
    elif shift_amount > 0:
        for i in range(length_input - shift_amount):
            output[i + shift_amount] = input_lst[i]
    else:
        s = - shift_amount
        for i in range(length_input - s):
            output[i] = input_lst[i + s]

    return output


def SHIFT_BY_VARIABLE_AMOUNT_continuous_diffusion_analysis(_input, input_size, shift_direction):
    """
    INPUT:

    - ``input`` -- **list**; a list representing a list of real numbers
    - ``input_size`` -- **integer**; size of the float list to be rotated
    - ``shift_direction`` -- **integer**; an integer indicating the direction of the shift, positive for right and
      negative for left

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions_continuous_diffusion_analysis import SHIFT_BY_VARIABLE_AMOUNT_continuous_diffusion_analysis
        sage: from decimal import *
        sage: _input = [0.01, 0.02, 0.004, 0.01, 0.02]
        sage: _input = [Decimal(float(_input[i])) for i in range(len(_input))]
        sage: input_size = 3
        sage: shift_direction = -1
        sage: output = SHIFT_BY_VARIABLE_AMOUNT_continuous_diffusion_analysis(
        ....:     _input, input_size, shift_direction
        ....: )
        sage: float(output[2]) == -0.44658816949
        True
    """
    input_lst = _input[:input_size]
    shift_amount_lst = _input[input_size:]
    shift_amount_lst = shift_amount_lst[::-1]

    if shift_direction < 0:
        return extended_left_shift_by_variable_amount(
            input_lst, shift_amount_lst
        )
    else:
        return extended_right_shift_by_variable_amount(
            input_lst, shift_amount_lst
        )


def SIGMA_continuous_diffusion_analysis(input_lst, rotation_amounts):
    """
    INPUT:

    - ``input_lst`` -- **list**; a list representing a list of real numbers
    - ``rotation_amounts`` -- **list**; list indicating the amount of the rotations
    """
    len_rotation_amounts = len(rotation_amounts)
    tmp = input_lst
    for i in range(len_rotation_amounts):
        rot_i = ROTATE_continuous_diffusion_analysis(input_lst, rotation_amounts[i])
        tmp = XOR_continuous_diffusion_analysis(tmp + rot_i, 2)

    return tmp


def XOR_continuous_diffusion_analysis(input_lst, number_of_inputs):
    """
    Compute the continuous generalization of a (or more) xor operation(s) [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    """
    block_len = len(input_lst) // number_of_inputs
    x = input_lst[0:block_len]
    y = input_lst[block_len:2 * block_len]
    z = XOR_continuous_diffusion_analysis_two_words(x + y)
    for j in range(number_of_inputs - 2):
        z = XOR_continuous_diffusion_analysis_two_words(
            z + input_lst[(j + 2) * block_len:(j + 2) * block_len + block_len]
        )

    return z


def XOR_continuous_diffusion_analysis_two_words(input_lst):
    """
    Compute the continuous generalization of a xor operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    """
    number_of_inputs = 2
    block_len = len(input_lst) // number_of_inputs
    x = input_lst[0:block_len]
    y = input_lst[block_len:2 * block_len]
    output = [Decimal(0.0)] * block_len
    for j in range(block_len):
        output[j] = Decimal(-1.0) * x[j] * y[j]

    return output


def MIX_COLUMN_generalized_continuous_diffusion_analysis(input_lst, mix_column_matrix, sbox_dictionary, word_size):
    """
    Compute the continuous generalization of a mix_column operation [MUR2020]_.

    INPUT:

    - ``input_lst`` -- **list**; is a list of real numbers in the range [-1, 1]
    - ``mix_column_matrix`` -- **list**; matrix representing the mix column matrix
    - ``sbox_dictionary`` -- **dictionary**; contains precomputations for the mix column operation
    - ``word_size`` -- **integer**; integer representing the word size

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions_continuous_diffusion_analysis import *
        sage: mix_column_matrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        sage: lookup_table_2 = [
        ....:     0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16,
        ....:     0x18, 0x1A, 0x1C, 0x1E, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E,
        ....:     0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x42, 0x44, 0x46,
        ....:     0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
        ....:     0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76,
        ....:     0x78, 0x7A, 0x7C, 0x7E, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E,
        ....:     0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E, 0xA0, 0xA2, 0xA4, 0xA6,
        ....:     0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
        ....:     0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6,
        ....:     0xD8, 0xDA, 0xDC, 0xDE, 0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE,
        ....:     0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE, 0x1B, 0x19, 0x1F, 0x1D,
        ....:     0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
        ....:     0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D,
        ....:     0x23, 0x21, 0x27, 0x25, 0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55,
        ....:     0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45, 0x7B, 0x79, 0x7F, 0x7D,
        ....:     0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
        ....:     0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D,
        ....:     0x83, 0x81, 0x87, 0x85, 0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5,
        ....:     0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5, 0xDB, 0xD9, 0xDF, 0xDD,
        ....:     0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
        ....:     0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED,
        ....:     0xE3, 0xE1, 0xE7, 0xE5
        ....: ]
        sage: lookup_table_3 = [
        ....:     0x0, 0x3, 0x6, 0x5, 0xc, 0xf, 0xa, 0x9, 0x18, 0x1b, 0x1e, 0x1d, 0x14,
        ....:     0x17, 0x12, 0x11, 0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28,
        ....:     0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21, 0x60, 0x63, 0x66, 0x65, 0x6c,
        ....:     0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71, 0x50,
        ....:     0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44,
        ....:     0x47, 0x42, 0x41, 0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8,
        ....:     0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1, 0xf0, 0xf3, 0xf6, 0xf5, 0xfc,
        ....:     0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1, 0xa0,
        ....:     0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4,
        ....:     0xb7, 0xb2, 0xb1, 0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88,
        ....:     0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81, 0x9b, 0x98, 0x9d, 0x9e, 0x97,
        ....:     0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a, 0xab,
        ....:     0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf,
        ....:     0xbc, 0xb9, 0xba, 0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3,
        ....:     0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea, 0xcb, 0xc8, 0xcd, 0xce, 0xc7,
        ....:     0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda, 0x5b,
        ....:     0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f,
        ....:     0x4c, 0x49, 0x4a, 0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73,
        ....:     0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a, 0x3b, 0x38, 0x3d, 0x3e, 0x37,
        ....:     0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a, 0xb,
        ....:     0x8, 0xd, 0xe, 0x7, 0x4, 0x1, 0x2, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c,
        ....:     0x19, 0x1a,
        ....: ]
        sage: evaluated_y_list_2, minus1_power_x_s_2 = compute_sbox_precomputations(lookup_table_2)
        sage: evaluated_y_list_3, minus1_power_x_s_3 = compute_sbox_precomputations(lookup_table_3)
        sage: sbox_precomputations = {}
        sage: sbox_precomputations["2"] = {}
        sage: sbox_precomputations["2"]["evaluated_boolean_function"] = evaluated_y_list_2
        sage: sbox_precomputations["2"]["minus1_power_x_t"] = minus1_power_x_s_2
        sage: sbox_precomputations["2"]["lookup_table"] = lookup_table_2
        sage: sbox_precomputations["3"] = {}
        sage: sbox_precomputations["3"]["evaluated_boolean_function"] = evaluated_y_list_3
        sage: sbox_precomputations["3"]["minus1_power_x_t"] = minus1_power_x_s_3
        sage: sbox_precomputations["3"]["lookup_table"] = lookup_table_3
        sage: input_lst = [Decimal(float(0.01*i)) for i in range(32)]
        sage: float(MIX_COLUMN_generalized_continuous_diffusion_analysis(
        ....:     input_lst, mix_column_matrix, sbox_precomputations, 8)[0]
        ....: )
        3.2256000000000004e-05
    """
    output_vector = [Decimal(float(0.0)) for _ in range(len(input_lst))]
    for i in range(len(mix_column_matrix)):

        if mix_column_matrix[i][0] == 0:
            temp = [Decimal(float(-1.0)) for _ in range(word_size)]
        elif mix_column_matrix[i][0] == 1:
            temp = input_lst[0:word_size]
        else:
            temp = SBOX_continuous_diffusion_analysis(
                input_lst[0:word_size],
                sbox_dictionary[str(mix_column_matrix[i][0])]
            )
        for j in range(1, len(mix_column_matrix[0])):
            if mix_column_matrix[i][j] == 0:
                temp1 = [Decimal(float(-1.0)) for _ in range(word_size)]
            elif mix_column_matrix[i][j] == 1:
                temp1 = input_lst[j * word_size:j * word_size + word_size]
            else:
                temp1 = SBOX_continuous_diffusion_analysis(
                    input_lst[j * word_size:j * word_size + word_size],
                    sbox_dictionary[str(mix_column_matrix[i][j])]
                )
            temp = XOR_continuous_diffusion_analysis(temp + temp1, 2)
        output_vector[i * word_size:i * word_size + word_size] = temp

    return output_vector


def _compute_continuous_function_for_sbox_component(dim, boolean_function, input_lst, minus1_power_x_t):
    """
    Create an extended component function from a `boolean_function` and `input_lst` (see [MUR2020]_)

    INPUT:

    - ``dim`` -- **integer**; threshold value used to express the input difference
    - ``boolean_function`` -- **list**; boolean function
    - ``input_lst`` -- **list**; array between -1 and 1
    - ``minus1_power_x_t`` -- **list**; array of elements -1 and 1
    """
    um_minus_minus1_power = 1 - minus1_power_x_t * input_lst
    um_minus_minus1_power_prod = um_minus_minus1_power.prod(axis=1)
    boolean_function_times_prod = multi_dot([boolean_function, um_minus_minus1_power_prod])

    return boolean_function_times_prod * Decimal(1 / (2 ** (dim - 1))) - 1


def compute_sbox_precomputations(sbox_lookup_table):
    """
    Compute precomputations for the extended sbox operation.

    This method evaluates all possible values of $y$ using the Boolean function $f$ in Theorem 1 [MUR2020]_. Also,
    this function computes all values $(-1)^y_i$ in that theorem.
    """
    dim = int(math.log(len(sbox_lookup_table), 2))
    y_shift = np.fromfunction(
        lambda i_input, j_input: i_input >> j_input, ((2 ** dim), dim), dtype=np.uint32
    )
    um = np.ones(((2 ** dim), dim), dtype=np.uint8)
    and_list = np.bitwise_and(y_shift, um, dtype=np.uint8)
    minus1_power_x_t = np.power(-1, and_list, dtype=np.int8)

    S = SBox(sbox_lookup_table)
    evaluated_y_list = []
    if sbox_lookup_table != [0 for _ in range(2 ** dim)]:
        for j in range(dim):
            sbox_bool_f_j = S.component_function(1 << j)
            y_row = []
            for yy in range(2 ** dim):
                y_row.append(int(sbox_bool_f_j(yy)))
            evaluated_y_list.append(y_row)
    else:
        evaluated_y_list = [[0 for _ in range(2 ** dim)] for _ in range(dim)]

    return evaluated_y_list, minus1_power_x_t


def create_lookup_table_by_matrix(mix_column_matrix, irreducible_polynomial_int_repr, degree):
    mix_column_dict = {}
    R = PolynomialRing(FiniteField(2 ** degree), 'x')
    irreducible_polynomial = R([int(x) for x in bin(irreducible_polynomial_int_repr)[2:]][::-1])
    k = QuotientRing(R, R.ideal(irreducible_polynomial), 'a')

    for i in range(len(mix_column_matrix)):
        for j in range(len(mix_column_matrix[0])):
            element = mix_column_matrix[i][j]
            element_str = str(element)
            if str(mix_column_matrix[i][j]) not in mix_column_dict:
                lookup_table_by_element = create_lookup_table_for_finite_field_element(
                    degree, element, k
                )
                mix_column_dict[element_str] = {}
                mix_column_dict[element_str]["lookup_table"] = lookup_table_by_element

                evaluated_y_list, minus1_power_x_s = compute_sbox_precomputations(
                    lookup_table_by_element
                )
                mix_column_dict[element_str]["evaluated_boolean_function"] = evaluated_y_list
                mix_column_dict[element_str]["minus1_power_x_t"] = minus1_power_x_s

    return mix_column_dict


def create_lookup_table_for_finite_field_element(degree, element, k):
    """ Creates a lookup table for an element of the finite field `k`. """
    lookup_table = []
    for i in range(2 ** degree):
        element_i = int_to_poly(i, degree, k.gen())
        lookup_table.append(
            poly_to_int(
                element_i * int_to_poly(element, degree, k.gen()),
                degree,
                k.gen()
            )
        )

    return lookup_table


def extended_and_bit(a, b):
    return Decimal(a * b + a + b - 1) * Decimal(0.5)


def extended_not_bit(input_bit):
    return -1 * Decimal(input_bit)


def extended_one_left_rotation_iteration(input_lst, rotation_amount, rotation_stage):
    rotation_amount_lst = [rotation_amount] * len(input_lst)
    len_input_lst = len(input_lst)
    max_number_of_bits_for_rotation_amount = math.log(len_input_lst, 2)

    if rotation_stage <= max_number_of_bits_for_rotation_amount:
        new_b = input_lst[2 ** rotation_stage:] + input_lst[:2 ** rotation_stage]
    else:
        new_b = np.array([-1] * int(2 ** max_number_of_bits_for_rotation_amount))
    new_lst = [list(x) for x in zip(new_b, input_lst, rotation_amount_lst)]

    return list(map(extended_two_bit_multiplexer, new_lst))


def extended_one_left_shift_iteration(input_lst, shift_amount, shift_stage):
    shift_amount_lst = np.array([shift_amount] * len(input_lst))
    len_input_lst = len(input_lst)
    max_number_of_bits_for_shift_amount = math.log(len_input_lst, 2)
    if shift_stage <= max_number_of_bits_for_shift_amount:
        new_b = np.array(input_lst[(2 ** shift_stage):] + [-1] * (2 ** shift_stage))
    else:
        new_b = np.array([-1] * int(2 ** max_number_of_bits_for_shift_amount))
    new_lst = np.array([list(x) for x in zip(list(new_b), list(input_lst), list(shift_amount_lst))])

    return list(map(extended_two_bit_multiplexer, new_lst))


def extended_one_right_rotation_iteration(input_lst, rotation_amount, shift_stage):
    rotation_amount_lst = [rotation_amount] * len(input_lst)
    new_b = input_lst[-2 ** shift_stage:] + input_lst[:-2 ** shift_stage]
    new_lst = [list(x) for x in zip(new_b, input_lst, rotation_amount_lst)]

    return list(map(extended_two_bit_multiplexer, new_lst))


def extended_one_right_shift_iteration(input_lst, shift_amount, shift_stage):
    shift_amount_lst = np.array([shift_amount] * len(input_lst))
    len_input_lst = len(input_lst)
    max_number_of_bits_for_shift_amount = math.log(len_input_lst, 2)
    if shift_stage <= max_number_of_bits_for_shift_amount:
        new_b = np.array([0] * (2 ** shift_stage) + input_lst[:len(input_lst) - (2 ** shift_stage)])
    else:
        new_b = np.array([-1] * int(2 ** max_number_of_bits_for_shift_amount))
    new_lst = np.array([list(x) for x in zip(list(new_b), list(input_lst), list(shift_amount_lst))])

    return list(map(extended_two_bit_multiplexer, new_lst))


def extended_left_rotation_by_variable_amount(input_lst, rotation_amount_lst):
    i = 0
    for rotation_amount in rotation_amount_lst:
        input_lst = extended_one_left_rotation_iteration(
            input_lst, rotation_amount, i
        )
        i += 1

    return input_lst


def extended_left_shift_by_variable_amount(input_lst, shift_amount_lst):
    i = 0
    for shift_amount in shift_amount_lst:
        input_lst = extended_one_left_shift_iteration(
            input_lst, shift_amount, i
        )
        i += 1

    return input_lst


def extended_right_rotation_by_variable_amount(input_lst, rotation_amount_lst):
    i = 0
    for rotation_amount in rotation_amount_lst:
        input_lst = extended_one_right_rotation_iteration(
            input_lst, rotation_amount, i
        )
        i += 1

    return input_lst


def extended_right_shift_by_variable_amount(input_lst, shift_amount_lst):
    i = 0
    for shift_amount in shift_amount_lst:
        input_lst = extended_one_right_shift_iteration(input_lst, shift_amount, i)
        i += 1

    return input_lst


def extended_two_bit_multiplexer(input_lst):
    i0 = input_lst[0]
    i1 = input_lst[1]
    a = input_lst[2]
    first_nand = extended_not_bit(extended_and_bit(i0, a))
    second_nand = extended_not_bit(extended_and_bit(a, a))
    third_nand = extended_not_bit(extended_and_bit(second_nand, i1))

    return extended_not_bit(extended_and_bit(first_nand, third_nand))


def get_mix_column_precomputations(mix_column_components):
    mix_column_precomputations = {}
    for mix_column_component in mix_column_components:
        mix_column_description = mix_column_component['description']
        mix_column_component_key = str(mix_column_description)
        if mix_column_component_key not in mix_column_precomputations:
            mix_column_matrix = mix_column_description[0]
            irreducible_polynomial_int_repr = mix_column_description[1]
            degree = mix_column_description[2]
            mix_column_precomputations[mix_column_component_key] = create_lookup_table_by_matrix(
                mix_column_matrix, irreducible_polynomial_int_repr, degree
            )

    return mix_column_precomputations


def get_sbox_precomputations(sbox_components):
    sbox_precomputations = dict()
    for sbox_component in sbox_components:
        sbox_lookup_table = sbox_component['description']
        if str(sbox_lookup_table) not in sbox_precomputations:
            evaluated_boolean_function, minus1_power_x_t = compute_sbox_precomputations(sbox_lookup_table)
            sbox_precomputations[str(sbox_lookup_table)] = {
                "evaluated_boolean_function": evaluated_boolean_function,
                "minus1_power_x_t": minus1_power_x_t,
                "lookup_table": sbox_lookup_table
            }

    return sbox_precomputations


def select_bits_continuous_diffusion_analysis(input_lst, bit_positions):
    output = []
    if not bit_positions:
        return output

    for i in range(len(bit_positions)):
        output = output + input_lst[bit_positions[i]:bit_positions[i] + 1]

    return output
