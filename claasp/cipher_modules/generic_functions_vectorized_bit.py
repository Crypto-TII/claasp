
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

import inspect
from operator import xor

import numpy as np

DEBUG_MODE = False


def bit_vector_to_integer(arr):
    """
    Converts a set of m bit strings of n bits (n <= 64) to m 64-bit unsigned integers

    INPUT:

    - ``arr`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per word.
    """
    output = np.zeros(shape=arr.shape[1], dtype=np.uint64)
    assert len(arr) <= 64 # Bitstrings of more than 64 bits are not supported by this function
    for i in range(len(arr)):
        ind = len(arr) - i - 1
        output += arr[i] * (2**ind)

    return output


def bit_vector_print_as_hex_values(name, x):
    """
    Prints a binary vector x as an hex value - used for debugging
    INPUT:

    - ``name`` -- **string** The name of the vector, for display purposes
    - ``x`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per word.
    """
    if isinstance(x, list):
        # For each value in the list, print column j of the numpy array
        for j in range(x[0].shape[1]):
            print(name, j, " : ", [hex(int.from_bytes(np.packbits(x[i][:, j],
                  axis=0).tobytes(), byteorder='big')) for i in range(len(x))])
    else:
        for j in range(x.shape[1]):
            print(name, j, " : ", hex(int.from_bytes(np.packbits(x[:, j], axis=0).tobytes(), byteorder='big')))


def bit_vector_select_word(input, bits, verbosity=False):
    """
    Returns the bits indexed in the bits list from the binary matrix input.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
    - ``bits`` -- **list**; is the array representing the indexes of the bits to extract
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if bits == list(range(len(input))):
        output = input
    else:
        output = input[bits]
    if verbosity:
        print(f'select_word input : {input.transpose()}')
        print(f'select_word bits : {bits}')
        print(f'select_word output : {output.transpose()}')
        print("---")
    return output


def bit_vector_SBOX(input, sbox, verbosity=False, output_bit_size = None):
    """
    Computes the SBox operation on binary values.

    INPUT:

      - ``input`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
      - ``sbox`` -- **np.array(dtype = np.uint8)** An integer numpy array representing the SBox.
      - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    tmp = np.zeros(shape=(8, input.shape[1]), dtype=np.uint8) # The SBox is assumed to be at most 8 bits
    tmp[-input.shape[0]:] = input
    int_val = np.packbits(tmp, axis=0)
    int_output = sbox[int_val]
    output = np.unpackbits(int_output, axis=0)
    if output_bit_size is None:
        output = output[-input.shape[0]:]
    else:
        output = output[-output_bit_size:]
    if verbosity:
        print("SBox")
        print("Input : ", input.transpose())
        print("Int input : ", int_val.transpose())
        print("Int output : ", int_output.transpose())
        print("Output : ", output.transpose())
        print("---")

    return output


def bit_vector_XOR(input, number_of_inputs, output_bit_size, verbosity=False):
    """
    Computes the XOR operation on binary values.

    INPUT:

    - ``input`` -- **list**; A list of binary numpy matrices to be XORed, each with one row per bit, and one column per sample.
    - ``number_of_inputs`` -- **integer**; is an integer representing the number of values to be xored together
    - ``output_bit_size`` -- **integer**; is an integer representing the bit size of the output
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    output = 0
    if number_of_inputs == len(input) and np.all([x.shape[0] == output_bit_size for x in input]):
        for i in range(number_of_inputs):
            output = output + input[i]
    else:
        assert np.all([x.shape[0] <= output_bit_size for x in input])
        output = np.zeros(shape=(output_bit_size, np.max([input[i].shape[1] for i in range(len(input))])), dtype=np.uint8)
        first_bit_index = 0
        for i in range(len(input)):
            current_input = input[i]
            bit_size = current_input.shape[0]
            output[first_bit_index:first_bit_index + bit_size] += current_input
            first_bit_index += bit_size
            if first_bit_index == output_bit_size:
                first_bit_index = 0

    output &= 1

    if DEBUG_MODE:
        intInputs = [bit_vector_to_integer(inputConcatenated[i * output_bit_size:(i + 1) * output_bit_size])
                     for i in range(len(inputConcatenated))]
        X = 0
        for i in range(len(inputConcatenated)):
            X ^= intInputs[i]
        assert np.all(X == bit_vector_to_integer(output))

    if verbosity:
        print_component_info(input, output, "XOR:")
        print("---")

    return output


def print_component_info(input, output, component_type):
    print(component_type)
    print([input[i].transpose() for i in range(len(input))])
    print(" Output:")
    print(output.transpose())



def bit_vector_CONCAT(input):
    """
    Concatenates binary values

    INPUT:

    - ``input`` -- **list**;  A list of binary numpy matrices to be concatenated, each with one row per bit, and one column per sample.
    """
    if len(input) == 1:
        return input[0]
    numCols = [input[i].shape[1] for i in range(len(input))]
    numRows = [input[i].shape[0] for i in range(len(input))]
    totalRows = np.sum(numRows)
    maxCols = np.max(numCols)
    output = np.empty(shape=(totalRows, maxCols), dtype=np.uint8)
    pos = 0
    for i in range(len(input)):
        rows = input[i].shape[0]
        if input[i].shape[1] != maxCols:
            output[pos:pos + rows] = np.broadcast_to(input[i], (rows, maxCols))
        else:
            output[pos:pos + rows] = input[i]
        pos += rows

    #    if verb:
    #        print_component_info(input, output, "CONCAT:")
    #        print("---")

    return output


def bit_vector_AND(input, number_of_inputs, output_bit_size, verbosity=False):
    """
    Computes the AND operation on binary vectors

    INPUT:

    - ``input`` -- **list**; A list of binary numpy matrices to be ANDed, each with one row per bit, and one column per sample.
    - ``number_of_inputs`` -- **integer**; is an integer representing the number of values to be xored together
    - ``output_bit_size`` -- **integer**; is an integer representing the bit size of the output
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    output = 1  # copy(inputConcatenated[0:output_bit_size])
    if number_of_inputs == len(input):
        for i in range(number_of_inputs):
            output = output & input[i]
    else:
        inputConcatenated = bit_vector_CONCAT(input)
        for i in range(number_of_inputs):
            output = output & inputConcatenated[i * output_bit_size:(i + 1) * output_bit_size]
    if verbosity:
        print("AND:")
        print([input[i].transpose() for i in range(len(input))])
        print([inputConcatenated[i].transpose() for i in range(len(inputConcatenated))])
        print(" Output:")
        print(output.transpose())

    return output


def bit_vector_OR(input, number_of_inputs, output_bit_size, verbosity=False):
    """
    Computes the OR operation on binary values

    INPUT:

    - ``input`` -- **list**; A list of binary numpy matrices to be ORed, each with one row per bit, and one column per sample.
    - ``number_of_inputs`` -- **integer**; is an integer representing the number of values to be xored together
    - ``output_bit_size`` -- **integer**; is an integer representing the bit size of the output
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    output = 0  # copy(inputConcatenated[0:output_bit_size])
    if number_of_inputs == len(input):
        for i in range(number_of_inputs):
            output = output | input[i]
    else:
        inputConcatenated = bit_vector_CONCAT(input)
        for i in range(number_of_inputs):
            output = output | inputConcatenated[i * output_bit_size:(i + 1) * output_bit_size]
    if verbosity:
        print_component_info(input, output, "OR:")

    return output


def bit_vector_NOT(input, verbosity=False):
    """
    Computes the NOT operation on binary values

    INPUT:

      - ``input`` -- -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
      - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    inputConcatenated = bit_vector_CONCAT(input)
    output = inputConcatenated ^ 1
    if verbosity:
        print_component_info(input, output, "NOT:")

    return output


def bit_vector_SHIFT_BY_VARIABLE_AMOUNT(input, input_size, shift_direction, verbosity=False):
    """
    Computes the shift by variable amount of binary values

    INPUT:

    - ``input`` -- -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
    - ``input_size`` -- **integer**; number of bits of the input string
    - ``shift_direction`` -- **integer**; the value of the shift, positive for right and
        negative for left
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    bits = np.uint8(np.log2(input_size))
    input0 = input[0]
    input1 = input[1]
    rotVals = np.zeros(shape=(8, input0.shape[1]), dtype=np.uint8)
    rotVals[8 - bits:8] = input1[input_size - bits:input_size]
    rotValsInt = np.packbits(rotVals, axis=0)[0]
    output = np.zeros(shape=input0.shape, dtype=np.uint8)
    for i in range(input_size):
        ind = np.where(rotValsInt == i)[0]
        output[:, ind] = np.roll(input0[:, ind], i * shift_direction, axis=0)
        if shift_direction == -1:
            output[input_size - i:, ind] = 0
        else:
            output[:i, ind] = 0

    if DEBUG_MODE:
        b = to_integer(input1) % input_size
        a = to_integer(input0)
        X = (a << b) & (2**input_size - 1)
        assert np.all(X == to_integer(output))

    if verbosity:
        print("VARIABLE_SHIFT:")

    return output


def bit_vector_MODADD(input, number_of_inputs, output_bit_size, verbosity=False):
    """
    Computes modular addition of binary inputs.

    INPUT:

    - ``input`` -- **list**; A list of binary numpy matrices to be added, each with one row per bit, and one column per sample.
    - ``number_of_inputs`` -- **integer**; is an integer representing the number of values to be added together
    - ``output_bit_size`` -- **integer**; is an integer representing the bit size of the output
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    if number_of_inputs == len(input):
        inputsList = input
    else:
        inputConcatenated = bit_vector_CONCAT(input)
        inputsList = [inputConcatenated[i * output_bit_size:(i + 1) * output_bit_size] for i in range(number_of_inputs)]
    Sum = 0  # np.zeros(shape=(1, inputsList[0].shape[1]), dtype=np.uint8)
    maxCols = np.max([x.shape[1] for x in inputsList])
    output = np.zeros(shape=(inputsList[0].shape[0], maxCols), dtype=np.uint8)
    word_size = output_bit_size
    for i in range(word_size):
        pos = word_size - 1 - i
        for j in range(len(inputsList)):
            Sum = Sum + inputsList[j][pos]
        output[pos] = (Sum & 1)
        Sum = (Sum >> 1)

    if DEBUG_MODE:
        intInputs = [to_integer(inputConcatenated[i * output_bit_size:(i + 1) * output_bit_size])
                     for i in range(len(inputConcatenated))]
        X = 0
        for i in range(len(inputConcatenated)):
            X = (X + intInputs[i]) % 2**word_size
        assert np.all(X == to_integer(output))

    if verbosity:
        print_component_info(input, output, "MODADD:")

    return output


def bit_vector_MODSUB(input, number_of_inputs, output_bit_size, verbosity=False):
    """
    Computes the modular subtraction of 2 binary inputs

    INPUT:

    - ``input`` -- **list**; A list of binary numpy matrices to be subtracted, each with one row per bit, and one column per sample.
    - ``number_of_inputs`` -- **integer**; is an integer representing the number of values to be subtracted
    - ``output_bit_size`` -- **integer**; is an integer representing the bit size of the output
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    assert number_of_inputs == 2  # Other cases not implemented
    inputConcatenated = bit_vector_CONCAT(input)
    Sum = np.uint8(0)
    inputsList = [0 for _ in range(3)]
    inputsList[0] = inputConcatenated[0:output_bit_size]
    inputsList[1] = 1 - inputConcatenated[output_bit_size:]  # negation
    one = np.zeros(shape=inputsList[0].shape, dtype=np.uint8)
    one[-1] += 1
    inputsList[2] = one
    output = np.zeros(shape=inputsList[0].shape, dtype=np.uint8)
    word_size = output_bit_size
    for i in range(word_size):
        pos = word_size - 1 - i
        for j in range(len(inputsList)):
            Sum = Sum + inputsList[j][pos]
        output[pos] = (Sum & 1)
        Sum = (Sum >> 1)
    if DEBUG_MODE:
        intInputs = [to_integer(inputConcatenated[i * output_bit_size:(i + 1) * output_bit_size])
                     for i in range(len(inputConcatenated))]
        X = (intInputs[0] - intInputs[1]) % (2**word_size)
        assert np.all(X == to_integer(output))

    if verbosity:
        print_component_info(input, output, "MODSUB:")

    return output


def bit_vector_ROTATE(input, rotation_amount, verbosity=False):
    """
    Computes the rotation of binary values.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
    - ``rotation_amount`` -- **integer**; the value of the rotation, positive for right rotation,
        negative for left rotation
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    inputConcatenated = bit_vector_CONCAT(input)
    output = np.roll(inputConcatenated, rotation_amount, axis=0)
    if verbosity:
        print("ROTATE:")
        print("  r   = {}".format(rotation_amount))
        print("Input : ", input)
        if inputConcatenated is not None:
            print("Input concatenated : ", inputConcatenated)
        print("Output : ", output)
        print("---")

    return output


def bit_vector_SHIFT(input, shift_amount, verbosity=False):
    """
    Computes the shift of binary values.
    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
    - ``shift_amount`` -- **integer**; the value of the shift, positive for right rotation,
        negative for left rotation
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    inputConcatenated = bit_vector_CONCAT(input)
    output = np.roll(inputConcatenated, shift_amount, axis=0)
    if shift_amount < 0:
        output[shift_amount:, :] = 0
    else:
        output[:shift_amount, :] = 0
    if verbosity:
        print("ROTATE:")
        print("  r   = {}".format(shift_amount))
        print(input.transpose())
        print(output.transpose())

    return output


def bit_vector_linear_layer(input, matrix, verbosity=False):
    """
    Computes the linear layer operation on binary values
    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
    - ``matrix`` -- **list**; a list of lists of 0s and 1s. len(matrix) should be equal to input.len
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    m8 = np.uint8(matrix)
    # Bit permutation case
    if np.sum(m8, axis=0).max() == 1:
        permutation_indexes = np.where(m8.T == 1)[1]
        output = input[permutation_indexes]
    else:
        output = input.transpose().dot(m8).transpose() % 2
    if verbosity:
        print("LINEAR LAYER:")
        print(input)
        print(output)

    return output


def bit_vector_mix_column(input, matrix, mul_table, input_size, verbosity=False):
    """
    Computes the mixcolumn operation on binary values

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
    - ``matrix`` -- **list**; a list of lists of 0s and 1s. len(matrix) should be equal to input.len
    - ``mul_tables`` -- **dictionary**; a dictionary such that mul_tables[x] is the multiplication table by x
    - ``input_size`` -- **integer**; an integer giving the bit size of the words
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    num_words = input.shape[0] // input_size
    output_int = np.zeros((num_words, input.shape[1]), dtype=np.uint8)
    words = [input[i * input_size: (i + 1) * input_size] for i in range(num_words)]
    words_int = [0 for _ in range(num_words)]
    for i in [*mul_table]:
        mul_table[i] = np.array(mul_table[i], dtype=np.uint8)
    for i in range(num_words):
        zeros = np.zeros(shape=(8, words[i].shape[1]), dtype=np.uint8)
        zeros[-words[i].shape[0]:] = words[i]
        words_int[i] = np.packbits(zeros, axis=0)
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            output_int[i] ^= mul_table[matrix[i][j]][words_int[j]][0]

    output = np.concatenate(
        np.swapaxes(np.array([(output_int >> (input_size - i - 1)) & 1 for i in range(input_size)], dtype=np.uint8), 0,
                    1))

    if verbosity:
        print("MIXCOLUMN:")
        print(input.transpose())
        print(output.transpose())
        print("---")

    return output


def bit_vector_mix_column_poly0(input, matrix, verbosity=False):
    """
    Computes the mixcolumn operation on binary values, for the special case where the polynomial is 0.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A binary numpy matrix with one row per bit, and one column per sample.
    - ``matrix`` -- **list**; a list of lists of 0s and 1s. len(matrix) should be equal to input.len
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    output = np.zeros(input.shape, dtype=np.uint8)
    word_size = input.shape[0] // len(matrix)
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            output[i * word_size:(i + 1) * word_size] ^= input[j * word_size:(j + 1) * word_size] * matrix[i][j]

    if verbosity:
        print("MIXCOLUMN poly 0:")
        print(input.transpose())
        print(output.transpose())
        print("---")

    return output

def bit_vector_fsr_binary(input, registers_info, clocks, verbosity=False):
    """
    Computes the result of the FSR operation on binary values.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per bit and one column per sample.
    - ``register_info`` -- **list of register** The description of the registers of fsr. register_info is defined as
      [length_of_register, fsr_polynomial, clock_polynomial]. For example,
      [[8, [[0],[1],[3],[2,5]], [[2],[10]]], [8, [[10],[11],[13],[12,15]]]]] represents two registers inside this
      fsr component. The first register has 8 bits and the fsr polynomial is x0+x1+x3+x2*x5, and its clock polynomial
      is x2+x10. The second register is also 8 bits, and its fsr polynomial is x10+x11+x13+x12*x15. Its clock is always
      true by default.
    - ``clocks`` -- **integer** Represents how many clocks would be done within this component.
    - ``verbosity`` -- **boolean**; (default: `False`); set this flag to True to print the input/output
    """
    output = bit_vector_CONCAT(input)

    number_of_registers = len(registers_info)
    registers_start = [0 for _ in range(number_of_registers)]
    registers_update_bit = [0 for _ in range(number_of_registers)]

    end = 0
    for i in range(number_of_registers):
        registers_start[i] = end
        end += registers_info[i][0]
        registers_update_bit[i] = end - 1

    for _ in range(clocks):
        output_bits = [np.zeros_like(output[0, :]) for __ in range(number_of_registers)]
        clock_bits = [np.zeros_like(output[0, :]) for __ in range(number_of_registers)]
        result = np.ones_like(output[0, :])

        for i in range(number_of_registers):
            for m in registers_info[i][1]:
                result.fill(1)
                for index in m:
                    result *= output[index, :]
                output_bits[i] = xor(result, output_bits[i])

            if len(registers_info[i]) > 2:
                for m in registers_info[i][2]:
                    result.fill(1)
                    for index in m:
                        result *= output[index, :]
                    clock_bits[i] = xor(result, clock_bits[i])
            else:
                clock_bits[i].fill(1)

        for i in range(number_of_registers):
            for k in range(registers_start[i], registers_update_bit[i]):
                output[k, :] = xor((clock_bits[i] * output[k+1, :]), (xor(clock_bits[i], 1) * output[k, :]))
            output[registers_update_bit[i], :] = xor((clock_bits[i] * output_bits[i]), (xor(clock_bits[i], 1) * output[registers_update_bit[i], :]))

    if verbosity:
        print("FSR")
        print("FSR description: ", registers_info)
        print("input: ", input)
        print("output: ", output)
        print("---")

    return output