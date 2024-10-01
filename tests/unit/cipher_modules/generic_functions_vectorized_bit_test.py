from claasp.cipher_modules.generic_functions_vectorized_bit import *
import numpy as np


def test_byte_vector_XOR():
    input_values = [np.arange(8, dtype = np.uint8).reshape((2,4)), np.arange(240, 248, dtype = np.uint8).reshape((2,4))]
    expected_result = input_values[0]^input_values[1]
    xor_result = byte_vector_XOR(input_values)
    assert np.all(xor_result == expected_result)

def test_byte_vector_OR():
    input_values = [np.arange(8, dtype = np.uint8).reshape((2,4)), np.arange(240, 248, dtype = np.uint8).reshape((2,4))]
    expected_result = input_values[0] | input_values[1]
    xor_result = byte_vector_OR(input_values)
    assert np.all(xor_result == expected_result)

def test_byte_vector_AND():
    input_values = [np.arange(8, dtype = np.uint8).reshape((2,4)), np.arange(240, 248, dtype = np.uint8).reshape((2,4))]
    expected_result = input_values[0]&input_values[1]
    xor_result = byte_vector_AND(input_values)
    assert np.all(xor_result == expected_result)

def test_byte_vector_NOT():
    input_values = [np.arange(8, dtype = np.uint8).reshape((2,4))]
    expected_result = input_values[0]^0xff
    xor_result = byte_vector_NOT(input_values)
    assert np.all(xor_result == expected_result)

def test_byte_vector_MODADD():
    bits = 48
    A = [0xcafecafecafe]
    B = [0xdecadecadeca]
    input_values = [integer_array_to_evaluate_vectorized_input(A, bits), integer_array_to_evaluate_vectorized_input(B, bits)]
    expected_result = integer_array_to_evaluate_vectorized_input([(A[0]+B[0]) % (2**bits)], bits)
    modadd_result = byte_vector_MODADD(input_values)
    assert np.all(modadd_result == expected_result)

def test_byte_vector_MODSUB():
    bits = 48
    A = [0xcafecafecafe]
    B = [0xdecadecadeca]
    input_values = [integer_array_to_evaluate_vectorized_input(A, bits), integer_array_to_evaluate_vectorized_input(B, bits)]
    expected_result = integer_array_to_evaluate_vectorized_input([(A[0]-B[0]) % (2**bits)], bits)
    modsub_result = byte_vector_MODSUB(input_values)

    assert np.all(modsub_result == expected_result)

def test_byte_vector_ROTATE():
    bits = 12
    input_values = integer_array_to_evaluate_vectorized_input([0, 0xfff], bits)
    rotate_result = byte_vector_ROTATE([input_values], rotation_amount = -4, input_bit_size=bits)
    assert np.all(rotate_result==input_values)

    bits = 12
    input_values = integer_array_to_evaluate_vectorized_input([0, 0xff], bits)
    expected_result = integer_array_to_evaluate_vectorized_input([0, 0x1fe], bits)
    rotate_result = byte_vector_ROTATE([input_values], rotation_amount = -1, input_bit_size=bits)

    print("In :", evaluate_vectorized_outputs_to_integers([input_values.transpose()], bits))
    print("Exp:", evaluate_vectorized_outputs_to_integers([expected_result.transpose()], bits))
    print("Out:",evaluate_vectorized_outputs_to_integers([rotate_result.transpose()], bits))

    assert np.all(rotate_result==expected_result)

