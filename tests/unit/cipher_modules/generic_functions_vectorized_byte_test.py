from claasp.cipher_modules.generic_functions_vectorized_byte import byte_vector_is_consecutive, \
    byte_vector_linear_layer, byte_vector_SBOX, integer_array_to_evaluate_vectorized_input, \
    cipher_inputs_to_evaluate_vectorized_inputs, get_number_of_bytes_needed_for_bit_size, \
    evaluate_vectorized_outputs_to_integers,byte_vector_select_all_words
import numpy as np


def test_byte_vector_is_consecutive():
    L = [3, 2, 1, 0]
    assert byte_vector_is_consecutive(L)


def test_integer_array_to_evaluate_vectorized_input():
    values = [0, 0xffff, 0xff, 0x01f0]
    bit_size = 16
    evaluate_vectorized_input = integer_array_to_evaluate_vectorized_input(values, bit_size)
    assert np.all(evaluate_vectorized_input.shape == (2, 4))
    assert np.all(evaluate_vectorized_input[:, 0] == 0)
    assert np.all(evaluate_vectorized_input[:, 1] == 255)
    assert np.all(evaluate_vectorized_input[:, 2] == (0, 255))
    assert np.all(evaluate_vectorized_input[:, 3] == (1, 240))

    values = [0, 0x1ffff, 0xff, 0xfffff]
    bit_size = 17
    evaluate_vectorized_input = integer_array_to_evaluate_vectorized_input(values, bit_size)
    assert np.all(evaluate_vectorized_input.shape == (3, 4))
    assert np.all(evaluate_vectorized_input[:, 0] == 0)
    assert np.all(evaluate_vectorized_input[:, 1] == (1, 255, 255))
    assert np.all(evaluate_vectorized_input[:, 2] == (0, 0, 255))
    assert np.all(evaluate_vectorized_input[:, 3] == (1, 255, 255))

    values = [2 ** 130 - 1, 0]
    bit_size = 129
    evaluate_vectorized_input = integer_array_to_evaluate_vectorized_input(values, bit_size)
    assert np.all(evaluate_vectorized_input.shape == (17, 2))
    assert np.all(evaluate_vectorized_input[1:, 0] == 255)
    assert evaluate_vectorized_input[0, 0] == 1
    assert np.all(evaluate_vectorized_input[:, 1] == 0)


def test_cipher_inputs_to_evaluate_vectorized_inputs():
    inputs = [0xff, 0]
    cipher_inputs_bit_size = [32, 64]
    evaluate_vectorized_inputs = cipher_inputs_to_evaluate_vectorized_inputs(inputs, cipher_inputs_bit_size)
    assert np.all(evaluate_vectorized_inputs[0].shape == (4, 1))
    assert np.all(evaluate_vectorized_inputs[1].shape == (8, 1))
    assert np.all(evaluate_vectorized_inputs[0][:, 0] == (0, 0, 0, 255))
    assert np.all(evaluate_vectorized_inputs[1] == 0)

    inputs = [[0xff, 0, 0xcafe], [0, 0, 2 ** 64 - 1]]
    cipher_inputs_bit_size = [32, 64]
    evaluate_vectorized_inputs = cipher_inputs_to_evaluate_vectorized_inputs(inputs, cipher_inputs_bit_size)
    assert np.all(evaluate_vectorized_inputs[0].shape == (4, 3))
    assert np.all(evaluate_vectorized_inputs[1].shape == (8, 3))
    assert np.all(evaluate_vectorized_inputs[0][:, 0] == (0, 0, 0, 255))
    assert np.all(evaluate_vectorized_inputs[0][:, 1] == (0, 0, 0, 0))
    assert np.all(evaluate_vectorized_inputs[0][:, 2] == (0, 0, 0xca, 0xfe))
    assert np.all(evaluate_vectorized_inputs[1][:, :2] == 0)
    assert np.all(evaluate_vectorized_inputs[1][:, 2] == 255)


def test_get_number_of_bytes_needed_for_bit_size():
    assert get_number_of_bytes_needed_for_bit_size(64) == 8
    assert get_number_of_bytes_needed_for_bit_size(63) == 8
    assert get_number_of_bytes_needed_for_bit_size(65) == 9


def test_evaluate_vectorized_outputs_to_integers():
    bit_size = 256
    values = [0, 2 ** bit_size - 1, 0xff]
    evaluate_vectorized_outputs = [integer_array_to_evaluate_vectorized_input(values, bit_size).transpose()]
    assert np.all(evaluate_vectorized_outputs_to_integers(evaluate_vectorized_outputs, bit_size) == values)
    bit_size = 6
    values = [np.uint8([0xff, 0x3f]).reshape(2, 1)]
    assert evaluate_vectorized_outputs_to_integers(values, bit_size) == [0x3f, 0x3f]
    values = [np.uint8([0x3f]).reshape(1, 1)]
    assert evaluate_vectorized_outputs_to_integers(values, bit_size) == 0x3f

def test_byte_vector_select_all_words():

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

    input_bit_size = 64
    num_cols = 2
    # Word operation, easy case
    A = np.arange(num_cols * input_bit_size//8, dtype = np.uint8).reshape(input_bit_size//8, num_cols)
    B = np.arange(num_cols * input_bit_size//8, 2*num_cols * input_bit_size//8, dtype = np.uint8).reshape(input_bit_size//8, num_cols)
    # Take the first 32 bits of A and last 32 bits of B
    unformated_inputs = [A, B]
    real_bits = [[list(range(32))], [list(range(32,64))]]
    real_inputs = [[0], [1]]
    number_of_inputs = 2
    words_per_input = get_number_of_bytes_needed_for_bit_size(input_bit_size//number_of_inputs)
    actual_input_bits = [64, 64]
    result = byte_vector_select_all_words(unformated_inputs, real_bits, real_inputs, number_of_inputs, words_per_input, actual_input_bits)
    assert np.all(result[0] == A[:4])
    assert np.all(result[1] == B[4:])

    # Unexpected leading bits are correctly removed
    input_bit_size = 10
    A = np.uint8([0xf1, 0x23]).reshape(2,1)
    unformated_inputs = [A]
    real_bits = [[list(range(10))]]
    real_inputs = [[0]]
    number_of_inputs = 1
    words_per_input = get_number_of_bytes_needed_for_bit_size(input_bit_size)
    actual_input_bits = [input_bit_size]
    result = byte_vector_select_all_words(unformated_inputs, real_bits, real_inputs, number_of_inputs, words_per_input, actual_input_bits)
    assert np.all(result[0].flatten() == [0x1, 0x23])

    # Odd case
    input_bit_size = 10
    A = np.uint8([0x3, 0x23]).reshape(2,1)
    unformated_inputs = [A]
    real_bits = [[list(range(1,9))]]
    real_inputs = [[0]]
    number_of_inputs = 1
    words_per_input = get_number_of_bytes_needed_for_bit_size(input_bit_size)
    actual_input_bits = [input_bit_size]
    result = byte_vector_select_all_words(unformated_inputs, real_bits, real_inputs, number_of_inputs, words_per_input, actual_input_bits)
    assert np.all(result[0].flatten() == [0x91])

def test_byte_vector_linear_layer():
    # Fancy block cipher linear layer
    linear_layer = [
        [0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1],
        [0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1],
        [1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1],
        [1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0],
        [1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0],
        [1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1],
        [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0],
        [1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1],
        [0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0],
        [0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0],
        [0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0],
        [1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1],
        [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1],
        [0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1],
        [0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1],
        [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1],
        [0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1],
        [0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0],
        [1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1],
        [0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1],
        [1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1]
    ]
    linear_layer_input = [np.ones((1,1), dtype = np.uint8) for i in range(24)]
    expected_output = [0xef, 0xc4, 0xa3]
    result = byte_vector_linear_layer(linear_layer_input, matrix=linear_layer)
    assert np.all(result.flatten().tolist() == expected_output)


