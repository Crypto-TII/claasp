from claasp.cipher_modules.generic_functions_vectorized_byte import byte_vector_is_consecutive, \
    byte_vector_linear_layer, byte_vector_SBOX, integer_array_to_evaluate_vectorized_input, \
    cipher_inputs_to_evaluate_vectorized_inputs, get_number_of_bytes_needed_for_bit_size, \
    evaluate_vectorized_outputs_to_integers,byte_vector_select_all_words,byte_vector_SBOX
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

def test_byte_vector_SBOX():
    # 4 bit case
    sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
    values = list(range(16))
    formated_values = integer_array_to_evaluate_vectorized_input(values, 4)
    sub = byte_vector_SBOX([formated_values], sbox, input_bit_size = 4)
    assert np.all(evaluate_vectorized_outputs_to_integers([sub.transpose()], 4) == sbox)

    # 9 bit case
    sbox = [
    167, 239, 161, 379, 391, 334, 9, 338, 38, 226, 48, 358, 452, 385, 90, 397,
    183, 253, 147, 331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177,
    175, 241, 489, 37, 206, 17, 0, 333, 44, 254, 378, 58, 143, 220, 81, 400,
    95, 3, 315, 245, 54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399, 76,
    165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176, 406, 507, 288, 223,
    501, 407, 249, 265, 89, 186, 221, 428, 164, 74, 440, 196, 458, 421, 350, 163,
    232, 158, 134, 354, 13, 250, 491, 142, 191, 69, 193, 425, 152, 227, 366, 135,
    344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27,

    487, 446, 482, 41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124,
    475, 384, 508, 53, 112, 170, 479, 151, 126, 169, 73, 268, 279, 321, 168, 364,
    363, 292, 46, 499, 393, 327, 324, 24, 456, 267, 157, 460, 488, 426, 309, 229,
    439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359, 52, 56, 120, 199, 277,
    465, 416, 252, 287, 246, 6, 83, 305, 420, 345, 153, 502, 65, 61, 244, 282,
    173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195, 430, 49, 79, 166, 330,
    280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454,
    132, 225, 203, 316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374,

    35, 103, 125, 427, 19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
    50, 116, 78, 410, 10, 205, 510, 171, 231, 45, 139, 467, 29, 86, 505, 32,
    72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473, 40, 119, 174, 355,
    185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369, 190,
    1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111,
    336, 318, 4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18,
    47, 85, 25, 497, 474, 289, 100, 269, 296, 478, 270, 106, 31, 104, 433, 84,
    414, 486, 394, 96, 99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,

    266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182, 509, 138, 210, 335, 133,
    311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481, 92, 404,
    485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
    312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398,
    284, 353, 105, 390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451,
    97, 30, 310, 219, 94, 160, 129, 493, 64, 179, 263, 102, 189, 207, 114, 402,
    438, 477, 387, 122, 192, 42, 381, 5, 145, 118, 180, 449, 293, 323, 136, 380,
    43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376, 436, 464, 59, 461
    ]
    values = list(range(2**9))
    formated_values = integer_array_to_evaluate_vectorized_input(values, 9)
    sub = byte_vector_SBOX([formated_values], sbox, input_bit_size = 9)
    assert np.all(evaluate_vectorized_outputs_to_integers([sub.transpose()], 9) == sbox)