# GPU version of generic_functions_vectorized_byte using CuPy
import cupy as cp
from functools import reduce
import math

NB = 8

def unpackbits_gpu(x):
    """Replace np.unpackbits(x, axis=0) using native CuPy operations."""
    x = cp.asarray(x)  # ← agregar esta línea
    bits = cp.arange(7, -1, -1, dtype=cp.uint8)
    return ((x[:, cp.newaxis, :] >> bits[cp.newaxis, :, cp.newaxis]) & 1).reshape(-1, x.shape[1]).astype(cp.uint8)


def packbits_gpu(x):
    """Replace np.packbits(x, axis=0) using native CuPy operations."""
    shifts = cp.arange(7, -1, -1, dtype=cp.int32)
    x_reshaped = x.reshape(-1, 8, x.shape[1])
    return cp.sum(x_reshaped * (2 ** shifts)[cp.newaxis, :, cp.newaxis], axis=1).astype(cp.uint8)

def byte_vector_XOR(input):
    input = [cp.asarray(x) for x in input]
    return reduce(lambda x, y: x ^ y, input)


def byte_vector_AND(input):
    input = [cp.asarray(x) for x in input]
    return reduce(lambda x, y: x & y, input)


def byte_vector_OR(input):
    input = [cp.asarray(x) for x in input]
    return reduce(lambda x, y: x | y, input)


def byte_vector_NOT(input):
    return ~cp.asarray(input[0])


def byte_vector_ROTATE(input, rotation_amount, input_bit_size):
    if input_bit_size % 8 != 0:
        bits_to_cut = 8 - (input_bit_size % 8)
        bin_input = unpackbits_gpu(input[0])
        rotated = cp.vstack([cp.zeros((bits_to_cut, bin_input.shape[1]), dtype=cp.uint8),
                             cp.roll(bin_input[bits_to_cut:, :], rotation_amount, axis=0)])
        ret = packbits_gpu(rotated)
    else:
        rot = rotation_amount
        wordRot = int(abs(rot) / NB)
        bitRot = int(abs(rot) % NB)
        sign = 1 if rot > 0 else -1
        ret = cp.roll(input[0], sign * wordRot, axis=0)
        if bitRot != 0:
            a = ret >> bitRot if sign > 0 else ret << bitRot
            b = ret << (8 - bitRot) if sign > 0 else ret >> (8 - bitRot)
            ret = a ^ cp.roll(b, sign, axis=0)
    return ret


def byte_vector_SHIFT(input, shift_amount):
    rot = shift_amount
    wordRot = abs(rot) // NB
    bitRot = int(abs(rot) % NB)
    sign = 1 if rot > 0 else -1
    ret = cp.roll(input[0], sign * wordRot, axis=0)
    if bitRot != 0:
        a = ret >> bitRot if sign > 0 else ret << bitRot
        b = ret << (8 - bitRot) if sign > 0 else ret >> (8 - bitRot)
        ret = a ^ cp.roll(b, sign, axis=0)
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


def byte_vector_MODADD(input):
    for i in range(len(input) - 1):
        if i == 0:
            a = input[0].copy()
            b = input[1].copy()
        else:
            a = c.copy()
            b = input[i + 1].copy()
        if a.shape[1] < b.shape[1]:
            carry = cp.zeros_like(b)
        else:
            carry = cp.zeros_like(a)
        c = a.copy()
        cbuf = carry.view(bool)[::a.itemsize]
        cbuf = cbuf[:-1]
        m = cp.iinfo(a.dtype).max
        while b.sum():
            cp.less(m - c[1:], b[1:], out=cbuf)
            c = reduce(lambda a, b: a + b, [c, b])
            b = carry.copy()
    return c


def byte_vector_SBOX(val, sbox, input_bit_size):
    """Apply SBox substitution to each sample."""
    sbox_gpu = cp.array(sbox, dtype=cp.uint8)
    if input_bit_size <= 8:
        output = sbox_gpu[val[0]]
    else:
        input_as_uint16 = (val[0][0, :].astype(cp.uint16) << 8) ^ val[0][1, :].astype(cp.uint16)
        sub = cp.array(sbox, dtype=cp.uint16)[input_as_uint16]
        output = cp.vstack([
            (sub >> 8).astype(cp.uint8),
            (sub & 0xff).astype(cp.uint8)
        ])
    return output

def get_number_of_bytes_needed_for_bit_size(bit_size):
    return math.ceil(bit_size / 8)


def byte_vector_is_consecutive(l):
    return cp.all(l[::-1] == cp.arange(l[-1], l[0] + 1).tolist())


def get_number_of_consecutive_bits(l):
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
    number_of_output_bits = int(sum([len(x) for x in real_bits[i]]))  # Python int
    if number_of_output_bits % 8 > 0:
        left_zero_padding = 8 - (number_of_output_bits % 8)
    else:
        left_zero_padding = 0
    bits_counter = 0
    binary_output = cp.zeros((left_zero_padding + number_of_output_bits, output[i].shape[1]), dtype=cp.uint8)
    for j in range(len(real_inputs[i])):
        val = unformatted_inputs[real_inputs[i][- j - 1]]
        bits_taken = len(real_bits[i][-j - 1])
        if actual_inputs_bits[real_inputs[i][-j - 1]] % 8 > 0:
            offset_for_first_byte = 8 - (actual_inputs_bits[real_inputs[i][-j - 1]] % 8)
        else:
            offset_for_first_byte = 0
        b_list = cp.array([x + offset_for_first_byte for x in real_bits[i][- j - 1]])
        binary_version = unpackbits_gpu(val)
        if j == 0:
            last_bit_position = None
        else:
            last_bit_position = -bits_counter
        binary_output[-bits_taken - bits_counter:last_bit_position] = binary_version[b_list, :]
        bits_counter += bits_taken
    output[i] = packbits_gpu(binary_output)


def byte_vector_select_all_words(unformated_inputs, real_bits, real_inputs, number_of_inputs, words_per_input,
                                 actual_inputs_bits):
    number_of_columns = [x.shape[1] for x in unformated_inputs]
    max_number_of_columns = cp.max(cp.array(number_of_columns))
    output = [0 for _ in range(number_of_inputs)]
    for i in range(number_of_inputs):
        pos = 0
        number_of_output_bits = int(sum([len(x) for x in real_bits[i]]))
        expected = list(range(actual_inputs_bits[real_inputs[i][0]]))
        actual = real_bits[i][0]
        if len(real_inputs[i]) == 1 and len(actual) == len(expected) and actual == expected:
            output[i] = unformated_inputs[real_inputs[i][0]]
            if number_of_output_bits % 8 > 0:
                left_byte_mask = 2 ** (number_of_output_bits % 8) - 1
            else:
                left_byte_mask = 0xff
            output[i][0, :] &= left_byte_mask
        else:
            output[i] = cp.zeros(shape=(words_per_input, int(max_number_of_columns)), dtype=cp.uint8)
            generate_formatted_inputs(actual_inputs_bits, i, output, pos, real_bits, real_inputs, unformated_inputs,
                                      words_per_input)
    return output


def cipher_inputs_to_evaluate_vectorized_inputs(cipher_inputs, cipher_inputs_bit_size):
    """Convert cipher inputs to GPU arrays using CPU for integer handling."""
    import numpy as np
    from claasp.cipher_modules.generic_functions_vectorized_byte import (
        cipher_inputs_to_evaluate_vectorized_inputs as cpu_convert
    )
    cpu_result = cpu_convert(cipher_inputs, cipher_inputs_bit_size)
    return [cp.asarray(x) for x in cpu_result]


def byte_vector_print_as_hex_values(name, x):
    import numpy as np
    if isinstance(x, list):
        for j in range(x[0].shape[1]):
            print(name, j, " : ", [hex(int.from_bytes(cp.asnumpy(x[i])[:, j].tobytes(), byteorder='big')) for i in range(len(x))])
    else:
        for j in range(x.shape[1]):
            print(name, j, " : ", hex(int.from_bytes(cp.asnumpy(x)[:, j].tobytes(), byteorder='big')))

def byte_vector_mix_column(input, matrix, mul_table, word_size):
    """Compute mix_column operation on GPU."""
    from functools import reduce
    tmp = cp.zeros(shape=(len(matrix) * input[0].shape[0], input[0].shape[1]), dtype=cp.uint8)
    for i in [*mul_table]:
        mul_table[i] = cp.array(mul_table[i], dtype=cp.uint8)
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            tmp[i] = reduce(lambda x, y: x ^ y, [tmp[i], mul_table[matrix[i][j]][input[j]]])
    if word_size >= 8:
        return tmp
    return byte_vector_select_all_words(
        unformated_inputs=[x.reshape(1, -1) for x in tmp],
        real_bits=[[list(range(word_size)) for _ in tmp]],
        real_inputs=[list(range(len(tmp)))],
        number_of_inputs=1,
        words_per_input=get_number_of_bytes_needed_for_bit_size(word_size * len(tmp)),
        actual_inputs_bits=[word_size for _ in tmp]
    )[0]


def byte_vector_mix_column_poly0(input, matrix, word_size):
    """Compute mix_column operation for poly=0 case on GPU."""
    tmp = cp.zeros(shape=(len(matrix) * input[0].shape[0], input[0].shape[1]), dtype=cp.uint8)
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            tmp[i * input[0].shape[0]:(i + 1) * input[0].shape[0]] = \
                tmp[i * input[0].shape[0]:(i + 1) * input[0].shape[0]] ^ matrix[i][j] * input[j]
    if word_size >= 8:
        return tmp
    return byte_vector_select_all_words(
        unformated_inputs=[x.reshape(1, -1) for x in tmp],
        real_bits=[[list(range(word_size)) for _ in tmp]],
        real_inputs=[list(range(len(tmp)))],
        number_of_inputs=1,
        words_per_input=get_number_of_bytes_needed_for_bit_size(word_size * len(tmp)),
        actual_inputs_bits=[word_size for _ in tmp]
    )[0]


def byte_vector_linear_layer(input, matrix):
    """Compute linear layer operation on GPU."""
    import numpy as np
    m8 = cp.array(np.uint8(matrix))
    if cp.sum(m8, axis=0).max() == 1:
        permutation_indexes = cp.where(m8.T == 1)[1]
        bin_result = cp.array(input)[permutation_indexes, 0, :]
    else:
        bin_result = cp.dot(m8.T, cp.array(input)[:, 0, :]) & 1
    if len(input) % 8 != 0:
        bin_result = cp.vstack([
            cp.zeros((8 - (len(input) % 8), input[0].shape[1]), dtype=cp.uint8),
            bin_result
        ])
    output = packbits_gpu(bin_result)
    return output

def evaluate_vectorized_outputs_to_integers(evaluate_vectorized_outputs, cipher_output_bit_size):
    """Convert GPU outputs to integers using CPU."""
    import numpy as np
    from claasp.cipher_modules.generic_functions_vectorized_byte import (
        evaluate_vectorized_outputs_to_integers as cpu_convert
    )
    cpu_outputs = [cp.asnumpy(x) if hasattr(x, 'get') else x for x in evaluate_vectorized_outputs]
    return cpu_convert(cpu_outputs, cipher_output_bit_size)