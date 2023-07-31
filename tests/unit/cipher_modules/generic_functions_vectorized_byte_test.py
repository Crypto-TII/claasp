from claasp.cipher_modules.generic_functions_vectorized_byte import byte_vector_is_consecutive


def test_byte_vector_is_consecutive():
    L = [3, 2, 1, 0]

    assert byte_vector_is_consecutive(L)
