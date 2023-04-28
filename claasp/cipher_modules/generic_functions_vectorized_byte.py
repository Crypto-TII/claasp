
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


import numpy as np
from copy import copy
from functools import reduce

NB = 8  # Number of bits of the representation


def byte_vector_print_as_hex_values(name, x):
    """
    Prints a byte vector x as an hex value - used for debugging

    INPUT:

    - ``name`` -- **string** The name of the vector, for display purposes
    - ``x`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte, and one column per word.
    """
    if isinstance(x, list):
        # For each value in the list, print column j of the numpy array
        for j in range(x[0].shape[1]):
            print(name, j, " : ", [hex(int.from_bytes(x[i][:, j].tobytes(), byteorder='big')) for i in range(len(x))])
    else:
        for j in range(x.shape[1]):
            print(name, j, " : ", hex(int.from_bytes(x[:, j].tobytes(), byteorder='big')))


def byte_vector_is_consecutive(l):
    """
    Return True if the bits in the list are consecutive.

    INPUT:

    - ``l`` -- **list**; a list of bit positions, in reverse order

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions_vectorized_byte import byte_vector_is_consecutive
        sage: L=[3, 2, 1, 0]
        sage: byte_vector_is_consecutive(L) == True
        True
    """
    return np.all(l[::-1] == np.arange(l[-1], l[0] + 1).tolist())


def byte_vector_select_all_words(unformatted_inputs, real_bits, real_inputs, number_of_inputs, words_per_input,
                                 actual_inputs_bits, verbosity=False):
    """
    Parses the inputs from the cipher into a list of numpy byte arrays, each corresponding to one input to the function.

    INPUT:

    - ``unformatted_inputs`` -- **list**; the variables involved in the operation, mapped by real_bits and real_inputs
    - ``real_bits`` -- **list**; a list of lists, where real_bits[0] contains all the lists of bits to be used for the
        first input of the operation
    - ``real_inputs`` -- **list**; a list of lists, where real_inputs[0] contains all the indexes of the variables to be
        used for the first input of the operation
    - ``number_of_inputs`` -- **integer**; an integer representing the number of inputs expected by the operation
    - ``words_per_input`` -- **integer**; the number of 8-bit words to be reserved for each of the inputs
    - ``actual_inputs_bits`` -- **integer**; the bit size of the variables in unformatted_inputs
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if verbosity:
        print("SELECT : ")
        print("Input =")
        print([x.transpose() for x in unformatted_inputs])

    number_of_columns = [unformatted_inputs[i].shape[1] for i in range(len(unformatted_inputs))]
    max_number_of_columns = np.max(number_of_columns)
    # Select bits
    output = [0 for _ in range(number_of_inputs)]
    for i in range(number_of_inputs):
        pos = 0
        if len(real_inputs[i]) == 1 and np.all(real_bits[i][0] == list(range(actual_inputs_bits[real_inputs[i][0]]))):
            output[i] = unformatted_inputs[real_inputs[i][0]]
        else:
            output[i] = np.zeros(shape=(words_per_input, max_number_of_columns), dtype=np.uint8)
            generate_formatted_inputs(actual_inputs_bits, i, output, pos, real_bits, real_inputs, unformatted_inputs,
                                      words_per_input)

    if verbosity:
        print("realInp :", real_inputs)
        print("realBits :", real_bits)
        print("ActualInputBits :", actual_inputs_bits)
        print("Output =")
        print([x.transpose() for x in output])
        print("/SELECT")

    return output


def generate_formatted_inputs(actual_inputs_bits, i, output, pos, real_bits,
                              real_inputs, unformatted_inputs, words_per_input):
    for j in range(len(real_inputs[i])):
        val = real_inputs[i][len(real_inputs[i]) - j - 1]
        b_list = real_bits[i][len(real_inputs[i]) - j - 1]
        b2 = copy(b_list)
        b2.reverse()
        k = 0
        while k < len(b2):
            b = b2[k]
            word_pos_in_output = (8 * words_per_input - pos - 1) // 8
            bit_left_shift_in_output = pos % 8
            bits_per_word_in_input = actual_inputs_bits[val] // unformatted_inputs[val].shape[0]
            word_pos_in_input = b // bits_per_word_in_input
            bit_pos_in_input = 8 - bits_per_word_in_input + (b % bits_per_word_in_input)

            if pos % 8 == 0 and k + 8 <= len(b2) and byte_vector_is_consecutive(b2[k:k + 8]) \
                    and b2[k + 7] % 8 == 0 and bits_per_word_in_input == 8:
                output[i][word_pos_in_output] = unformatted_inputs[val][word_pos_in_input]
                pos = pos + 8
                k = k + 8
            elif pos % 4 == 0 and k + 4 <= len(b2) and byte_vector_is_consecutive(b2[k:k + 4]) \
                    and b2[k + 3] % 4 == 0 and bits_per_word_in_input == 4:
                if pos % 8 == 0:
                    output[i][word_pos_in_output] ^= unformatted_inputs[val][word_pos_in_input]
                    pos = pos + 4
                    k = k + 4
                elif pos % 8 == 4:
                    output[i][word_pos_in_output] ^= unformatted_inputs[val][word_pos_in_input] << 4
                    pos = pos + 4
                    k = k + 4
            else:
                output[i][word_pos_in_output] ^= ((unformatted_inputs[val][word_pos_in_input] >> (
                        8 - 1 - bit_pos_in_input)) & 1) << bit_left_shift_in_output
                pos = pos + 1
                k = k + 1


def byte_vector_SBOX(val, sbox, verbosity=False):
    """
    Computes the result of the SBox operation.

    INPUT:

    - ``val`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte and one column per sample.
    - ``sbox`` --  **np.array(dtype = np.uint8)** An integer numpy array representing the SBox.
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if verbosity:
        print("SBox")
        print("Input : ", val[0].transpose())
        print("Output : ", sbox[val[0]].transpose())
        print("---")

    return sbox[val[0]]


def byte_vector_XOR(input, verbosity=False):
    """
    Computes the result of the XOR operation.

    INPUT:
    - ``input`` -- **list**; A list of numpy byte matrices to be XORed, each with one row per byte, and one column per
        sample.
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if verbosity:
        print("XOR")
        print("Input =")
        print([x.transpose() for x in input])

    output = reduce(lambda x, y: x ^ y, input)
    if verbosity:
        print("Output = ")
        print(output.transpose())
        print("/XOR")
        print("\n")

    return output


def byte_vector_AND(input, verbosity=False):
    """
    Computes the result of the AND operation

    INPUT:

    INPUT:
    - ``input`` -- **list**; A list of numpy byte matrices to be ANDed, each with one row per byte, and one column per
        sample.
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output.
    """
    output = reduce(lambda x, y: x & y, input)

    if verbosity:
        print_component_info(input, output, "AND:")

    return output


def byte_vector_OR(input, verbosity=False):
    """
    Computes the result of the OR operation.

    INPUT:

    INPUT:
    - ``input`` -- **list**; A list of numpy byte matrices to be ORed, each with one row per byte, and one column per
        sample.
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output.
    """
    output = reduce(lambda x, y: x | y, input)

    if verbosity:
        print_component_info(input, output, "OR:")

    return output


def byte_vector_NOT(input, verbosity=False):
    """
    Computes the result of the NOT operation.

    INPUT:

    - ``input`` -- **list**; A list of one numpy byte matrix to be negated, with one row per byte, and one column per
        sample
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    output = ~input[0]

    if verbosity:
        print_component_info(input, output, "NOT:")

    return output


def byte_vector_SHIFT_BY_VARIABLE_AMOUNT(input, input_size, shift_direction, verbosity=False):
    """
    Computes the bitwise shift by variable amount operation.

    INPUT:

    - ``input`` -- **list**; A list of one numpy byte matrix to be shifted, with one row per byte, and one column per sample.
    - ``input_size`` -- **integer**; size in bits of value to be shifted
    - ``shift_direction`` -- **integer**; the value of the shift, positive for right and
        negative for left
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output

    """
    bits = np.uint8(np.log2(input_size))
    input0 = input[0][0:input_size // 8]
    input1 = input[0][-input_size // 8:]
    assert bits <= 8
    rotVals = input1[-1] & (2 ** bits - 1)
    output = np.zeros(shape=input0.shape, dtype=np.uint8)
    for i in range(input_size):
        ind = np.where(rotVals == i)
        if len(ind[0]) > 0:
            output[:, ind[0]] = byte_vector_SHIFT([input0[:, ind[0]]],
                                                  i * shift_direction)  # np.roll(input0[:, ind], i*shift_direction, axis=0)
    if verbosity:
        print("VARIABLE_SHIFT:")
        print("Output with shape ", output.shape)
        print(output)

    return output


def byte_vector_MODADD(input, verbosity=False):
    """
    Computes the result of the MODADD operation.

    INPUT:

    - ``input`` -- **list**; A list of numpy byte matrices to be added, each with one row per byte, and one column per sample.
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if verbosity:
        print("MODADD")
        print("Input =")
        print(input)
    for i in range(len(input) - 1):
        if i == 0:
            a = input[0].copy()
            b = input[1].copy()
        else:
            a = c.copy()
            b = input[i + 1].copy()
        if a.shape[1] < b.shape[1]:
            carry = np.zeros_like(b)
        else:
            carry = np.zeros_like(a)

        c = a.copy()
        cbuf = carry.view(bool)[::a.itemsize]
        cbuf = cbuf[:-1]
        m = np.iinfo(a.dtype).max
        while b.sum():
            np.less(m - c[1:], b[1:], out=cbuf)
            c = reduce(lambda a, b: a + b, [c, b])
            b = carry.copy()
    if verbosity:
        print("Output:")
        print(c)
        print("/MODADD")

    return c


def byte_vector_MODSUB(input, verbosity=False):
    """
    Computes the result of the MODSUB operation.

    INPUT:

    - ``input`` -- **list**; A list of 2 numpy byte matrices to be subtracted, each with one row per byte, and one column per sample.
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """

    assert len(input) == 2  # Other cases not implemented

    inputsList = [0 for _ in range(3)]
    inputsList[0] = input[0]
    inputsList[1] = ~input[1]  # negation
    one = np.zeros(shape=inputsList[0].shape, dtype=np.uint8)
    one[-1] += 1
    a = byte_vector_MODADD([inputsList[0], inputsList[1]])
    output = byte_vector_MODADD([a, one])

    if verbosity:
        print_component_info(input, output, "MODSUB:")

    return output


def byte_vector_ROTATE(input, rotation_amount, verbosity=False):
    """
    Computes the result of the bitwise ROTATE operation.

    INPUT:

    - ``input`` -- **list**; A list of one numpy byte matrix to be rotated, with one row per byte, and one column per sample.
    - ``input_size`` -- **integer**; size in bits of value to be shifted
    - ``rotation_amount`` -- **integer**; the value of the rotation, positive for right and
        negative for left
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if verbosity:
        print("ROTATE, ", rotation_amount)
        print("Input = ")
        print(input)
    rot = rotation_amount
    wordRot = int(abs(rot) / NB)
    bitRot = int(abs(rot) % NB)
    sign = 1 if rot > 0 else -1
    ret = np.roll(input[0], sign * wordRot, axis=0)
    if bitRot != 0:
        a = ret >> bitRot if sign > 0 else ret << bitRot
        b = ret << (8 - bitRot) if sign > 0 else ret >> (8 - bitRot)
        ret = a ^ np.roll(b, sign, axis=0)
    if verbosity:
        print(input[0].transpose())
        print("Output =")
        print(ret)

    return ret


def byte_vector_SHIFT(input, shift_amount, verbosity=False):
    """
    Computes the result of the bitwise SHIFT operation.

    INPUT:

    - ``input`` -- **list**; A list of one numpy byte matrix to be shifted, with one row per byte, and one column per sample.
    - ``input_size`` -- **integer**; size in bits of value to be shifted
    - ``shift_smount`` -- **integer**; the value of the shift, positive for right and
        negative for left
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if verbosity:
        print("SHIFT, ", shift_amount)
        print("Input = ")
        print(input)

    rot = shift_amount
    wordRot = abs(rot) // NB
    bitRot = int(abs(rot) % NB)
    sign = 1 if rot > 0 else -1
    ret = np.roll(input[0], sign * wordRot, axis=0)
    if bitRot != 0:
        a = ret >> bitRot if sign > 0 else ret << bitRot
        b = ret << (8 - bitRot) if sign > 0 else ret >> (8 - bitRot)
        ret = a ^ np.roll(b, sign, axis=0)

    if sign > 0:
        if wordRot != 0:
            ret[:wordRot] = 0
        mask = ((0xff) >> bitRot) & 0xff
        ret[wordRot] = ret[wordRot] & mask
    else:
        if wordRot != 0:
            ret[-wordRot:] = 0
        mask = ((0xff) << bitRot) & 0xff
        ret[-1 - wordRot] = ret[-1 - wordRot] & mask

    if verbosity:
        print("Wordrot:", wordRot, ", bitrot:", bitRot, ", Mask = ", hex(mask))
        print("Output =")
        print(ret)

    return ret


def byte_vector_linear_layer(input, matrix):
    """
    Computes the linear layer operation.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte, and one column per sample.
    - ``matrix`` -- **list**; a list of lists of 0s and 1s
    """
    return np.packbits(np.dot(np.array([x[0] for x in input], dtype=np.uint8).T, matrix) & 1, axis=1).transpose()


def byte_vector_mix_column(input, matrix, mul_table, verbosity=False):
    """
    Computes the mix_column operation.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte, and one column per sample.
    - ``matrix`` -- **list**; a list of lists of integers
    - ``mul_tables`` -- **dictionary**; a dictionary giving the multiplication table by x at key x
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if verbosity:
        print("MIXCOLUMN:")
        print(input.transpose())
    output = np.zeros(shape=(len(input), input[0].shape[1]), dtype=np.uint8)
    for i in [*mul_table]:
        mul_table[i] = np.array(mul_table[i], dtype=np.uint8)
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            output[i] = reduce(lambda x, y: x ^ y, [output[i], mul_table[matrix[i][j]][input[j]]])
    if verbosity:
        print(output.transpose())
        print("---")

    return output


def byte_vector_mix_column_poly0(input, matrix, verbosity=False):
    """
    Computes the mix_column operation, special case where poly=0.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte, and one column per byte.
    - ``matrix`` -- **list**; a list of lists of integers
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if verbosity:
        print("MIXCOLUMN poly 0:")
        print(input.transpose())
    output = np.zeros(shape=(len(input) * input[0].shape[0], input[0].shape[1]), dtype=np.uint8)
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            # for k in range(len(matrix)):
            # print(output.shape,  i, j, input[j].shape, output[i].shape, matrix[i][j])
            #   output[i] = output[i]^(matrix[i][j]*input[j])
            output[i * input[0].shape[0]:(i + 1) * input[0].shape[0]] = \
                output[i * input[0].shape[0]:(i + 1) * input[0].shape[0]] ^ matrix[i][j] * input[j]
            # reduce(lambda x, y:x^y, [output[i], matrix[i][j]*input[j]])
    if verbosity:
        print(output.transpose())
        print("---")

    return output


def print_component_info(input, output, component_type):
    print(component_type)
    print("Inputs : ")
    print([input[i].transpose() for i in range(len(input))])
    print(" Output:")
    print(output.transpose())
