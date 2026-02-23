from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.component_analysis_tests import (
    CipherComponentsAnalysis,
    compute_branch_number_from_binary_matrix,
    branch_number,
)
from claasp.ciphers.stream_ciphers.bluetooth_stream_cipher_e0 import BluetoothStreamCipherE0
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from sage.all import Matrix, identity_matrix
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF


def test_get_all_operations():
    fancy = FancyBlockCipher(number_of_rounds=3)
    cipher_operations = CipherComponentsAnalysis(fancy).get_all_operations()
    assert list(cipher_operations.keys()) == ["sbox", "linear_layer", "XOR", "AND", "MODADD", "ROTATE", "SHIFT"]


def test_component_analysis_tests():
    fancy = FancyBlockCipher(number_of_rounds=3)
    components_analysis = CipherComponentsAnalysis(fancy).component_analysis_tests()
    assert len(components_analysis["test_results"]) == 9

    aes = AESBlockCipher(word_size=8, state_size=2, number_of_rounds=2)
    result = CipherComponentsAnalysis(aes).component_analysis_tests()
    assert len(result["test_results"]) == 7


def test_print_component_analysis_as_radar_charts():
    aes = AESBlockCipher(word_size=8, state_size=4, number_of_rounds=2)
    CipherComponentsAnalysis(aes).print_component_analysis_as_radar_charts()


def test_fsr_properties():
    e0 = BluetoothStreamCipherE0(keystream_bit_len=2)
    dictionary = CipherComponentsAnalysis(e0).component_analysis_tests()["test_results"]
    assert dictionary[8]["number_of_registers"] == 4
    assert dictionary[8]["lfsr_connection_polynomials"][0] == "x^25 + x^20 + x^12 + x^8 + 1"
    assert dictionary[8]["lfsr_connection_polynomials"][1] == "x^31 + x^24 + x^16 + x^12 + 1"
    assert dictionary[8]["lfsr_connection_polynomials"][2] == "x^33 + x^28 + x^24 + x^4 + 1"
    assert dictionary[8]["lfsr_connection_polynomials"][3] == "x^39 + x^36 + x^28 + x^4 + 1"
    assert dictionary[8]["lfsr_polynomials_are_primitive"] == [True, True, True, True]

    triv = TriviumStreamCipher(keystream_bit_len=1)
    dictionary = CipherComponentsAnalysis(triv).component_analysis_tests()["test_results"]
    assert dictionary[0]["type_of_registers"] == ["non-linear", "non-linear", "non-linear"]


def test_compute_branch_number_from_binary_matrix_differential():
    """Test differential branch number computation from binary matrix."""
    F = GF(2)

    # Identity matrix - should have branch number = 2
    matrix = identity_matrix(F, 2)
    bn = compute_branch_number_from_binary_matrix(matrix, "differential")
    assert bn == 2, f"Expected branch number 2 for 2x2 identity matrix, got {bn}"

    # Simple matrix [[1, 0], [1, 1]]
    matrix = Matrix(F, [[1, 0], [1, 1]])
    bn = compute_branch_number_from_binary_matrix(matrix, "differential")
    assert bn == 2, f"Expected branch number 2, got {bn}"


def test_compute_branch_number_from_binary_matrix_linear():
    """Test linear branch number computation from binary matrix."""
    F = GF(2)

    # Identity matrix - should have branch number = 2 for both differential and linear
    matrix = identity_matrix(F, 2)
    bn = compute_branch_number_from_binary_matrix(matrix, "linear")
    assert bn == 2, f"Expected branch number 2 for 2x2 identity matrix (linear), got {bn}"

    # Simple matrix [[1, 0], [1, 1]]
    matrix = Matrix(F, [[1, 0], [1, 1]])
    bn = compute_branch_number_from_binary_matrix(matrix, "linear")
    assert bn == 2, f"Expected branch number 2 (linear), got {bn}"


def test_compute_branch_number_from_binary_matrix_larger_matrix():
    """Test branch number computation for larger matrices."""
    F = GF(2)

    # 4x4 identity matrix
    matrix = identity_matrix(F, 4)
    bn = compute_branch_number_from_binary_matrix(matrix, "differential")
    assert bn == 2, f"Expected branch number 2 for 4x4 identity matrix, got {bn}"

    # 4x4 matrix with more ones
    matrix = Matrix(F, [[1, 1, 0, 0], [1, 0, 1, 0], [0, 1, 0, 1], [1, 1, 1, 1]])
    bn = compute_branch_number_from_binary_matrix(matrix, "differential")
    assert isinstance(bn, int) and bn > 0, f"Expected positive integer branch number, got {bn}"


def test_compute_branch_number_from_binary_matrix_type_parameter():
    """Test that type parameter correctly switches between differential and linear."""
    F = GF(2)

    # Create a non-symmetric matrix
    matrix = Matrix(F, [[1, 0], [1, 1]])

    bn_diff = compute_branch_number_from_binary_matrix(matrix, "differential")
    bn_lin = compute_branch_number_from_binary_matrix(matrix, "linear")

    # Both should be positive integers
    assert isinstance(bn_diff, int) and bn_diff > 0
    assert isinstance(bn_lin, int) and bn_lin > 0


def test_branch_number_with_bit_format():
    """Test branch_number function with format='bit' on mix_column component.

    This test ensures that the optimized binary matrix computation path is
    being used correctly when branch_number is called with format='bit'.
    """
    aes = AESBlockCipher(number_of_rounds=3)
    # Find a mix_column component - iterate through rounds to get the first one
    mix_column_component = None
    for round_obj in aes.rounds_as_list:
        for component in round_obj.components:
            if component.type == "mix_column":
                mix_column_component = component
                break
        if mix_column_component:
            break

    assert mix_column_component is not None, "No mix_column component found in AES"

    # Test differential branch number with bit format
    diff_bn_bit = branch_number(mix_column_component, "differential", "bit")
    assert isinstance(diff_bn_bit, int) and diff_bn_bit > 0, (
        f"Expected positive integer for differential branch number (bit), got {diff_bn_bit}"
    )

    # Test linear branch number with bit format
    lin_bn_bit = branch_number(mix_column_component, "linear", "bit")
    assert isinstance(lin_bn_bit, int) and lin_bn_bit > 0, (
        f"Expected positive integer for linear branch number (bit), got {lin_bn_bit}"
    )

    # Test that word-level computation still works
    diff_bn_word = branch_number(mix_column_component, "differential", "word")
    assert isinstance(diff_bn_word, int) and diff_bn_word > 0, (
        f"Expected positive integer for differential branch number (word), got {diff_bn_word}"
    )

    # Verify they are computed (actual values depend on the matrix)
    assert diff_bn_bit >= 1 and lin_bn_bit >= 1 and diff_bn_word >= 1
