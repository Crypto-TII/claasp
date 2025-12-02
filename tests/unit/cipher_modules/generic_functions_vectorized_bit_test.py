import numpy as np
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_IDEA_MODMUL


def test_bit_vector_modmul():
    # Test 1: Standard IDEA multiplication (3 * 5) mod 65537 = 15
    a = np.zeros((16, 1), dtype=np.uint8)
    a[14, 0] = 1  # bit 1
    a[15, 0] = 1  # bit 0 -> value 3
    b = np.zeros((16, 1), dtype=np.uint8)
    b[13, 0] = 1  # bit 2
    b[15, 0] = 1  # bit 0 -> value 5
    result = bit_vector_IDEA_MODMUL([a, b], 2, 16, 65537)
    expected = np.zeros((16, 1), dtype=np.uint8)
    expected[12, 0] = 1  # bit 3
    expected[13, 0] = 1  # bit 2
    expected[14, 0] = 1  # bit 1
    expected[15, 0] = 1  # bit 0 -> value 15
    assert np.array_equal(result, expected)

    # Test 2: Mapping (0 * 1) mod 65537 with 0 representing 2^16
    a = np.zeros((16, 1), dtype=np.uint8)  # 0 treated as 2^16
    b = np.zeros((16, 1), dtype=np.uint8)
    b[15, 0] = 1  # 1
    result = bit_vector_IDEA_MODMUL([a, b], 2, 16, 65537)
    expected = np.zeros((16, 1), dtype=np.uint8)  # Maps back to 0
    assert np.array_equal(result, expected)

    # Test 3: Both operands zero (0 * 0) -> (2^16 * 2^16) mod 65537 = 1
    a = np.zeros((16, 1), dtype=np.uint8)
    b = np.zeros((16, 1), dtype=np.uint8)
    result = bit_vector_IDEA_MODMUL([a, b], 2, 16, 65537)
    expected = np.zeros((16, 1), dtype=np.uint8)
    expected[15, 0] = 1  # Result is 1
    assert np.array_equal(result, expected)
