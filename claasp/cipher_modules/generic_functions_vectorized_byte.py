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
from functools import reduce
import math

NB = 8  # Number of bits of the representation


def integer_array_to_evaluate_vectorized_input(values, bit_size):
    """
    Converts the bit_size integers from the values array to the representation accepted by evaluate_vectorized, a numpy matrix
    of unsigned 8-bit integers (one row per byte, one column per value). If needed, the values are padded with zeroes
    on the left. If the cipher takes multiple inputs, this function needs to be called once for each.

    INPUT:
    - ``values`` -- **list** A list of integers
    - ``bit_size`` -- **integer** The bit size of the elements of values.
    """
    num_bytes = get_number_of_bytes_needed_for_bit_size(bit_size)
    # math.ceil(bit_size / 8)
    values_as_np = np.array(values, dtype=object) & (2 ** bit_size - 1)
    #print(f"In conv function : {values=}, {values_as_np=}")
    evaluate_vectorized_input = (np.uint8([(values_as_np >> ((num_bytes - j - 1) * 8)) & 0xff
                                           for j in range(num_bytes)]).reshape((num_bytes, -1)))
    return evaluate_vectorized_input


def cipher_inputs_to_evaluate_vectorized_inputs(cipher_inputs, cipher_inputs_bit_size):
    """
    Converts cipher_inputs from integers to the format expected by evaluate_vectorized.
    If cipher_inputs is a list of integers (one per input position), then the function returns a list of numpy matrices
    that can be used to evaluate a single set of inputs to the cipher (with a similar api to cipher.evaluate).
    If cipher_inputs is a list of lists of integers (one per input position), then the function returns a list of numpy
    matrices that can be used to evaluate multiple set of inputs to the cipher.
    The produced matrices contain one row per byte, and one column per value.
    If needed, the values are padded with zeroes on the left.

    INPUT:
    - ``cipher_inputs`` -- **list** A list of lists of integers (one per cipher input position)
    - ``cipher_inputs_bit_size`` -- **list** The inputs bit sizes of the cipher.
    """
    assert len(cipher_inputs) == len(cipher_inputs_bit_size), "The cipher_input_to_evaluate_vectorized_input expects" \
                                                              "one list of inputs per value in " \
                                                              "cipher_inputs_bit_size "
    evaluate_vectorized_inputs = []
    for i, bit_size in enumerate(cipher_inputs_bit_size):
        evaluate_vectorized_inputs.append(integer_array_to_evaluate_vectorized_input(cipher_inputs[i], bit_size))
    return evaluate_vectorized_inputs


def get_number_of_bytes_needed_for_bit_size(bit_size):
    return math.ceil(bit_size / 8)


def evaluate_vectorized_outputs_to_integers(evaluate_vectorized_outputs, cipher_output_bit_size):
    """
    Converts the outputs of evaluate_vectorized (a list containing a single numpy matrix) to a list of integers
    (one per output/row of the matrix)

    INPUT:
    - ``evaluate_vectorized_outputs`` -- **list** A list containing one numpy array returned by evaluate_vectorized
    - ``cipher_output_bit_size`` -- **integer** The output bit size of the cipher
    """
    shifts = np.flip(
        np.array([i * 8 for i in range(get_number_of_bytes_needed_for_bit_size(cipher_output_bit_size))], dtype=object))
    int_vals = (np.sum(evaluate_vectorized_outputs[0] << shifts, axis=1) & (2 ** cipher_output_bit_size - 1)).tolist()
    if len(int_vals) == 1:
        return int_vals[0]
    else:
        return int_vals


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
                                 actual_inputs_bits):
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
    """
    number_of_columns = [unformatted_inputs[i].shape[1] for i in range(len(unformatted_inputs))]
    max_number_of_columns = np.max(number_of_columns)
    output = [0 for _ in range(number_of_inputs)]
    for i in range(number_of_inputs):
        pos = 0
        number_of_output_bits = np.sum([len(x) for x in real_bits[i]])
        if len(real_inputs[i]) == 1 and np.all(real_bits[i][0] == list(range(actual_inputs_bits[real_inputs[i][0]]))):
            output[i] = unformatted_inputs[real_inputs[i][0]]
            if number_of_output_bits % 8 > 0:
                left_byte_mask = 2 ** (number_of_output_bits % 8) - 1
            else:
                left_byte_mask = 0xffff
            output[i][0, :] &= left_byte_mask
        else:
            output[i] = np.zeros(shape=(words_per_input, max_number_of_columns), dtype=np.uint8)
            generate_formatted_inputs(actual_inputs_bits, i, output, pos, real_bits, real_inputs, unformatted_inputs,
                                      words_per_input)
    return output


def get_number_of_consecutive_bits(l):
    """
    Return the number of consecutive numbers from the start of list l, in decreasing order.

    INPUT:

    - ``l`` -- **list**; a list of bit positions, in reverse order

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions_vectorized_byte import get_number_of_consecutive_bits
        sage: L=[4, 3, 5, 7, 2]
        sage: get_number_of_consecutive_bits(L) == 2
        True
    """

    number_of_consecutive_bits = 0
    pred = l[0]
    for i in range(1, len(l)):
        if l[i] == pred - 1:
            pred = l[i]
            number_of_consecutive_bits += 1
        else:
            break
    return number_of_consecutive_bits


def generate_formatted_inputs(actual_inputs_bits, i, output, pos, real_bits,
                              real_inputs, unformatted_inputs, words_per_input):
    number_of_output_bits = np.sum([len(x) for x in real_bits[i]])
    if number_of_output_bits % 8 > 0:
        left_zero_padding = 8 - (number_of_output_bits % 8)
    else:
        left_zero_padding = 0
    bits_counter = 0
    binary_output = np.zeros((left_zero_padding + number_of_output_bits, output[i].shape[1]), dtype=np.uint8)

    for j in range(len(real_inputs[i])):
        val = unformatted_inputs[real_inputs[i][- j - 1]]
        bits_taken = len(real_bits[i][-j - 1])
        if actual_inputs_bits[real_inputs[i][-j - 1]] % 8 > 0:
            offset_for_first_byte = 8 - (actual_inputs_bits[real_inputs[i][-j - 1]] % 8)
        else:
            offset_for_first_byte = 0
        b_list = np.array(real_bits[i][- j - 1]) + offset_for_first_byte
        binary_version = np.unpackbits(val, axis=0)
        # print("="*10)
        # print(f"{b_list=}")
        # print(f"{binary_version=}")
        # print(f"{offset_for_first_byte=}")
        # print(f"{left_zero_padding=}")

        if j == 0:
            last_bit_position = None
        else:
            last_bit_position = -bits_counter
        binary_output[-bits_taken - bits_counter:last_bit_position] = binary_version[b_list, :]
        # binary_output[-bits_taken-bits_counter:-bits_counter] = binary_version[b_list, :]

        bits_counter += bits_taken
    output[i] = np.packbits(binary_output, axis=0)


def byte_vector_SBOX(val, sbox, input_bit_size):
    """
    Computes the result of the SBox operation.

    INPUT:

    - ``val`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte and one column per sample.
    - ``sbox`` --  **np.array(dtype = np.uint8)** An integer numpy array representing the SBox.
    """
    if input_bit_size <= 8:
        output = np.uint8(sbox)[val[0]]
    else:
        assert val[0].shape[0] == 2, "The inputs cannot be larger than two bytes each."
        input_as_uint16 = (np.uint16(val[0][0, :]) << 8) ^ val[0][1, :]
        sub = np.uint16(sbox)[input_as_uint16]
        output = np.uint8(np.vstack([sub >> 8, sub & 0xff]))
    return output


def byte_vector_XOR(input):
    """
    Computes the result of the XOR operation.

    INPUT:
    - ``input`` -- **list**; A list of numpy byte matrices to be XORed, each with one row per byte, and one column per
        sample.
    """
    output = reduce(lambda x, y: x ^ y, input)
    return output


def byte_vector_AND(input):
    """
    Computes the result of the AND operation

    INPUT:

    INPUT:
    - ``input`` -- **list**; A list of numpy byte matrices to be ANDed, each with one row per byte, and one column per
        sample.
    """
    output = reduce(lambda x, y: x & y, input)
    return output


def byte_vector_OR(input):
    """
    Computes the result of the OR operation.

    INPUT:

    INPUT:
    - ``input`` -- **list**; A list of numpy byte matrices to be ORed, each with one row per byte, and one column per
        sample.
    """
    output = reduce(lambda x, y: x | y, input)
    return output


def byte_vector_NOT(input):
    """
    Computes the result of the NOT operation.

    INPUT:

    - ``input`` -- **list**; A list of one numpy byte matrix to be negated, with one row per byte, and one column per
        sample
    """
    output = ~input[0]
    return output


def byte_vector_SHIFT_BY_VARIABLE_AMOUNT(input, input_size, shift_direction):
    """
    Computes the bitwise shift by variable amount operation.

    INPUT:

    - ``input`` -- **list**; A list of one numpy byte matrix to be shifted, with one row per byte, and one column per sample.
    - ``input_size`` -- **integer**; size in bits of value to be shifted
    - ``shift_direction`` -- **integer**; the value of the shift, positive for right and
        negative for left

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
    return output


def byte_vector_MODADD(input):
    """
    Computes the result of the MODADD operation.

    INPUT:

    - ``input`` -- **list**; A list of numpy byte matrices to be added, each with one row per byte, and one column per sample.
    """
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
    return c


def byte_vector_MODSUB(input):
    """
    Computes the result of the MODSUB operation.

    INPUT:

    - ``input`` -- **list**; A list of 2 numpy byte matrices to be subtracted, each with one row per byte, and one column per sample.
    """

    assert len(input) == 2  # Other cases not implemented

    inputsList = [0 for _ in range(3)]
    inputsList[0] = input[0]
    inputsList[1] = ~input[1]  # negation
    one = np.zeros(shape=inputsList[0].shape, dtype=np.uint8)
    one[-1] += 1
    a = byte_vector_MODADD([inputsList[0], inputsList[1]])
    output = byte_vector_MODADD([a, one])

    return output


def byte_vector_ROTATE(input, rotation_amount, input_bit_size):
    """
    Computes the result of the bitwise ROTATE operation.

    INPUT:

    - ``input`` -- **list**; A list of one numpy byte matrix to be rotated, with one row per byte, and one column per sample.
    - ``input_size`` -- **integer**; size in bits of value to be shifted
    - ``rotation_amount`` -- **integer**; the value of the rotation, positive for right and
        negative for left
    """
    if input_bit_size % 8 != 0:
        bits_to_cut = 8 - (input_bit_size % 8)
        bin_input = np.unpackbits(input[0], axis=0)
        rotated = np.vstack([np.zeros((bits_to_cut, bin_input.shape[1]), dtype=np.uint8),
                             np.roll(bin_input[bits_to_cut:, :], rotation_amount)])
        ret = np.packbits(rotated, axis=0)
    else:
        rot = rotation_amount
        wordRot = int(abs(rot) / NB)
        bitRot = int(abs(rot) % NB)
        sign = 1 if rot > 0 else -1
        ret = np.roll(input[0], sign * wordRot, axis=0)
        if bitRot != 0:
            a = ret >> bitRot if sign > 0 else ret << bitRot
            b = ret << (8 - bitRot) if sign > 0 else ret >> (8 - bitRot)
            ret = a ^ np.roll(b, sign, axis=0)
    return ret


def byte_vector_SHIFT(input, shift_amount):
    """
    Computes the result of the bitwise SHIFT operation.

    INPUT:

    - ``input`` -- **list**; A list of one numpy byte matrix to be shifted, with one row per byte, and one column per sample.
    - ``input_size`` -- **integer**; size in bits of value to be shifted
    - ``shift_smount`` -- **integer**; the value of the shift, positive for right and
        negative for left
    """
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
    return ret


def byte_vector_linear_layer(input, matrix):
    """
    Computes the linear layer operation.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte, and one column per sample.
    - ``matrix`` -- **list**; a list of lists of 0s and 1s
    """
    m8 = np.uint8(matrix)
    # Bit permutation case
    if np.sum(m8, axis=0).max() == 1:
        permutation_indexes = np.where(m8.T == 1)[1]
        bin_result = np.uint8(input)[permutation_indexes, 0, :]
    else:
        bin_result = np.dot(m8.T, np.uint8(input)[:, 0, :]) & 1
    if len(input) % 8 != 0:
        bin_result = np.vstack([np.zeros((8 - (len(input) % 8), input[0].shape[1]), dtype=np.uint8), bin_result])
    output = np.packbits(bin_result, axis=0)

    return output


def byte_vector_mix_column(input, matrix, mul_table, word_size):
    """
    Computes the mix_column operation.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte, and one column per sample.
    - ``matrix`` -- **list**; a list of lists of integers
    - ``mul_tables`` -- **dictionary**; a dictionary giving the multiplication table by x at key x
    """
    assert word_size == 4 or word_size == 8, "Vectorized evaluation of mix_columns does not support word sizes other than 8 and 4"
    tmp = np.zeros(shape=(len(input), input[0].shape[1]), dtype=np.uint8)
    for i in [*mul_table]:
        mul_table[i] = np.array(mul_table[i], dtype=np.uint8)
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            tmp[i] = reduce(lambda x, y: x ^ y, [tmp[i], mul_table[matrix[i][j]][input[j]]])
    if word_size < 8:
        output = np.uint8([(tmp[2 * i, :] << 4) ^ tmp[2 * i + 1, :] for i in range(len(input) // 2)])
        return output
    else:
        return tmp


def byte_vector_mix_column_poly0(input, matrix, word_size):
    """
    Computes the mix_column operation, special case where poly=0.

    INPUT:

    - ``input`` -- **np.array(dtype = np.uint8)** A numpy matrix with one row per byte, and one column per byte.
    - ``matrix`` -- **list**; a list of lists of integers
    """
    assert word_size == 4 or word_size == 8, "Vectorized evaluation of mix_columns does not support word sizes other than 8 and 4"
    tmp = np.zeros(shape=(len(input), input[0].shape[1]), dtype=np.uint8)
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            tmp[i * input[0].shape[0]:(i + 1) * input[0].shape[0]] = \
                tmp[i * input[0].shape[0]:(i + 1) * input[0].shape[0]] ^ matrix[i][j] * input[j]

    if word_size < 8:
        output = np.uint8([(tmp[2 * i, :] << 4) ^ tmp[2 * i + 1, :] for i in range(len(input) // 2)])
        return output
    else:
        return tmp
