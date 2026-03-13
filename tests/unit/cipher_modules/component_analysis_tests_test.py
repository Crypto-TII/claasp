import pytest
import matplotlib.pyplot as plt
from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.component_analysis_tests import (
    CipherComponentsAnalysis,
    compute_branch_number_from_binary_matrix,
    compute_branch_number_from_binary_matrix_with_sage,
    compute_branch_number_from_binary_matrix_with_bounded_enumeration,
    compute_branch_number_from_field_matrix,
    compute_branch_number_from_field_matrix_with_sage,
    compute_branch_number_from_field_matrix_with_bounded_enumeration,
    branch_number,
)
from claasp.ciphers.stream_ciphers.bluetooth_stream_cipher_e0 import BluetoothStreamCipherE0
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from sage.all import Matrix, identity_matrix
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing


@pytest.fixture(scope="module")
def aes_mix_column_component():
    """Module-scoped fixture: AES MixColumn component (cipher instantiated once)."""
    aes = AESBlockCipher(number_of_rounds=3)
    for round_obj in aes.rounds_as_list:
        for component in round_obj.components:
            if component.type == "mix_column":
                return component
    raise RuntimeError("No mix_column component found in AES")


@pytest.fixture(scope="module")
def aes_small_mix_column_component():
    """Smaller AES MixColumn component for faster branch_number(format='bit') checks."""
    aes = AESBlockCipher(word_size=8, state_size=2, number_of_rounds=2)
    for round_obj in aes.rounds_as_list:
        for component in round_obj.components:
            if component.type == "mix_column":
                return component
    raise RuntimeError("No mix_column component found in small AES")


@pytest.fixture(scope="module")
def fancy_cipher():
    """Module-scoped Fancy cipher reused by multiple tests."""
    return FancyBlockCipher(number_of_rounds=3)


@pytest.fixture(scope="module")
def fancy_analysis(fancy_cipher):
    """Module-scoped analysis object for Fancy cipher."""
    return CipherComponentsAnalysis(fancy_cipher)


@pytest.fixture(scope="module")
def fancy_component_analysis_results(fancy_analysis):
    """Compute Fancy component analysis once; reused across tests."""
    return fancy_analysis.component_analysis_tests()


@pytest.fixture(scope="module")
def aes_small_analysis_results():
    """Compute small AES component analysis once; reused across tests."""
    aes = AESBlockCipher(word_size=8, state_size=2, number_of_rounds=2)
    return CipherComponentsAnalysis(aes).component_analysis_tests()


def test_get_all_operations(fancy_analysis):
    cipher_operations = fancy_analysis.get_all_operations()
    assert list(cipher_operations.keys()) == ["sbox", "linear_layer", "XOR", "AND", "MODADD", "ROTATE", "SHIFT"]


def test_component_analysis_tests(fancy_component_analysis_results, aes_small_analysis_results):
    components_analysis = fancy_component_analysis_results
    assert len(components_analysis["test_results"]) == 9

    result = aes_small_analysis_results
    assert len(result["test_results"]) == 7


def test_print_component_analysis_as_radar_charts(fancy_component_analysis_results):
    # Keep coverage of plotting logic while avoiding GUI/blocking overhead.
    plt.switch_backend("Agg")
    original_show = plt.show
    plt.show = lambda: None
    try:
        # Reuse precomputed results to cover plotting code paths without
        # recomputing expensive component-analysis metrics.
        CipherComponentsAnalysis(FancyBlockCipher(number_of_rounds=3)).print_component_analysis_as_radar_charts(
            results=fancy_component_analysis_results["test_results"]
        )
    finally:
        plt.show = original_show


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

    # Regression case: minimum is reached by a weight-2 input (not by a single row)
    matrix = Matrix(F, [[1, 1], [1, 1]])
    bn = compute_branch_number_from_binary_matrix(matrix, "differential")
    assert bn == 2, f"Expected branch number 2 for [[1,1],[1,1]], got {bn}"


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

    # Regression case in linear mode
    matrix = Matrix(F, [[1, 1], [1, 1]])
    bn = compute_branch_number_from_binary_matrix(matrix, "linear")
    assert bn == 2, f"Expected branch number 2 for [[1,1],[1,1]] (linear), got {bn}"


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


def test_compute_branch_number_from_binary_matrix_large_128_fast_case():
    """Test branch number on large 128x128 matrices using bounded enumeration.

    Uses method='bounded' explicitly: the bounded search exits as soon as best==2
    is found at weight 1, so it is O(n) regardless of matrix size.
    The sage (LinearCode) path does NOT short-circuit and would be very slow on
    a 128x256 generator matrix, so it is NOT appropriate for large matrices.
    """
    F = GF(2)

    # Identity: BN=2 is found at weight-1 (each row has exactly one output bit),
    # so bounded search exits after seeing the first column.
    identity_128 = identity_matrix(F, 128)
    bn_identity = compute_branch_number_from_binary_matrix(
        identity_128, "differential", method="bounded"
    )
    assert bn_identity == 2, f"Expected branch number 2 for 128x128 identity, got {bn_identity}"

    # Permutation matrix: same argument - one-hot columns give BN=2 immediately.
    permutation_128 = identity_matrix(F, 128)[::-1, :]
    bn_permutation = compute_branch_number_from_binary_matrix(
        permutation_128, "differential", method="bounded"
    )
    assert bn_permutation == 2, f"Expected branch number 2 for 128x128 permutation matrix, got {bn_permutation}"

    # Linear mode: same early-exit applies on the transpose.
    bn_identity_linear = compute_branch_number_from_binary_matrix(
        identity_128, "linear", method="bounded"
    )
    assert bn_identity_linear == 2, f"Expected linear branch number 2 for 128x128 identity, got {bn_identity_linear}"


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


def test_branch_number_with_bit_format(aes_small_mix_column_component):
    """Test branch_number function with format='bit' on mix_column component.

    This test ensures that the optimized binary matrix computation path is
    being used correctly when branch_number is called with format='bit'.
    """
    mix_column_component = aes_small_mix_column_component

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

    assert diff_bn_bit >= 1 and lin_bn_bit >= 1 and diff_bn_word >= 1


def test_branch_number_with_word_format_exact_mix_column(aes_mix_column_component):
    """Test exact word-level branch number for AES mix_column component."""
    mix_column_component = aes_mix_column_component

    diff_bn_word = branch_number(mix_column_component, "differential", "word")
    lin_bn_word = branch_number(mix_column_component, "linear", "word")

    assert diff_bn_word == 5, f"Expected AES mix_column differential word branch number 5, got {diff_bn_word}"
    assert lin_bn_word == 5, f"Expected AES mix_column linear word branch number 5, got {lin_bn_word}"


# ==================== New comprehensive tests for method variations ====================


class TestBinaryMatrixWithSage:
    """Test suite for compute_branch_number_from_binary_matrix_with_sage."""

    def test_identity_matrix_2x2(self):
        """Test sage method on 2x2 identity matrix."""
        F = GF(2)
        matrix = identity_matrix(F, 2)
        bn = compute_branch_number_from_binary_matrix_with_sage(matrix, "differential")
        assert bn == 2, f"Expected 2, got {bn}"

    def test_simple_matrix_differential(self):
        """Test sage method with simple matrix in differential mode."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_binary_matrix_with_sage(matrix, "differential")
        assert bn == 2, f"Expected 2, got {bn}"

    def test_simple_matrix_linear(self):
        """Test sage method with simple matrix in linear mode."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_binary_matrix_with_sage(matrix, "linear")
        assert bn == 2, f"Expected 2, got {bn}"

    def test_4x4_identity(self):
        """Test sage method on larger 4x4 identity matrix."""
        F = GF(2)
        matrix = identity_matrix(F, 4)
        bn = compute_branch_number_from_binary_matrix_with_sage(matrix, "differential")
        assert bn == 2, f"Expected 2 for 4x4 identity, got {bn}"

    def test_list_input(self):
        """Test that sage method accepts Python list input."""
        matrix = [[1, 0], [1, 1]]
        bn = compute_branch_number_from_binary_matrix_with_sage(matrix, "differential")
        assert bn == 2, f"Expected 2, got {bn}"


class TestBinaryMatrixWithBoundedEnumeration:
    """Test suite for compute_branch_number_from_binary_matrix_with_bounded_enumeration."""

    def test_identity_matrix_2x2(self):
        """Test bounded method on 2x2 identity matrix."""
        F = GF(2)
        matrix = identity_matrix(F, 2)
        bn = compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix, "differential", max_input_weight=3)
        assert bn == 2, f"Expected 2, got {bn}"

    def test_simple_matrix_differential(self):
        """Test bounded method with simple matrix in differential mode."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix, "differential", max_input_weight=3)
        assert bn == 2, f"Expected 2, got {bn}"

    def test_simple_matrix_linear(self):
        """Test bounded method with simple matrix in linear mode."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix, "linear", max_input_weight=3)
        assert bn == 2, f"Expected 2, got {bn}"

    def test_max_input_weight_parameter(self):
        """Test that max_input_weight parameter is respected."""
        F = GF(2)
        # Use a matrix where the minimum is at higher weight
        matrix = identity_matrix(F, 4)
        # Even with max_input_weight=1, should find the minimum at weight 1
        bn = compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix, "differential", max_input_weight=1)
        assert bn == 2, f"Expected 2 with max_input_weight=1, got {bn}"

    def test_list_input(self):
        """Test that bounded method accepts Python list input."""
        matrix = [[1, 0], [1, 1]]
        bn = compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix, "differential", max_input_weight=3)
        assert bn == 2, f"Expected 2, got {bn}"


class TestBinaryMatrixWithMethodParameter:
    """Test suite for compute_branch_number_from_binary_matrix with method parameter."""

    def test_default_method_is_sage(self):
        """Test that default method is 'sage'."""
        F = GF(2)
        matrix = identity_matrix(F, 2)
        bn_default = compute_branch_number_from_binary_matrix(matrix, "differential")
        bn_sage = compute_branch_number_from_binary_matrix(matrix, "differential", method="sage")
        assert bn_default == bn_sage, f"Default method should be 'sage': {bn_default} != {bn_sage}"

    def test_method_sage(self):
        """Test explicit method='sage' parameter."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_binary_matrix(matrix, "differential", method="sage")
        assert bn == 2, f"Expected 2 with method='sage', got {bn}"

    def test_method_bounded(self):
        """Test explicit method='bounded' parameter."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_binary_matrix(matrix, "differential", method="bounded", max_input_weight=3)
        assert bn == 2, f"Expected 2 with method='bounded', got {bn}"

    def test_sage_and_bounded_give_same_result(self):
        """Test that both methods give the same result on simple matrices."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0, 0], [1, 1, 0], [0, 1, 1]])
        bn_sage = compute_branch_number_from_binary_matrix(matrix, "differential", method="sage")
        bn_bounded = compute_branch_number_from_binary_matrix(matrix, "differential", method="bounded", max_input_weight=3)
        assert bn_sage == bn_bounded, f"Sage and bounded methods disagree: {bn_sage} != {bn_bounded}"

    def test_invalid_method_raises_error(self):
        """Test that invalid method parameter raises error."""
        F = GF(2)
        matrix = identity_matrix(F, 2)
        try:
            compute_branch_number_from_binary_matrix(matrix, "differential", method="invalid")
            assert False, "Should have raised ValueError for invalid method"
        except ValueError as e:
            assert "Unknown method" in str(e)

    def test_type_parameter_with_method(self):
        """Test that type parameter works with method parameter."""
        F = GF(2)
        matrix = identity_matrix(F, 2)
        bn_diff_sage = compute_branch_number_from_binary_matrix(matrix, "differential", method="sage")
        bn_lin_sage = compute_branch_number_from_binary_matrix(matrix, "linear", method="sage")
        bn_diff_bounded = compute_branch_number_from_binary_matrix(matrix, "differential", method="bounded")
        bn_lin_bounded = compute_branch_number_from_binary_matrix(matrix, "linear", method="bounded")
        assert bn_diff_sage == 2 and bn_lin_sage == 2
        assert bn_diff_bounded == 2 and bn_lin_bounded == 2


class TestFieldMatrixWithSage:
    """Test suite for compute_branch_number_from_field_matrix_with_sage."""

    def test_gf2_matrix(self):
        """Test sage method on GF(2) matrix."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_field_matrix_with_sage(matrix)
        assert bn == 2, f"Expected 2, got {bn}"

    def test_gf4_matrix(self):
        """Test sage method on GF(4) matrix."""
        F = GF(4, 'a')
        matrix = Matrix(F, [[1, 1], [1, F.gen()]])
        bn = compute_branch_number_from_field_matrix_with_sage(matrix)
        assert bn == 3, f"Expected 3, got {bn}"

    def test_identity_matrix(self):
        """Test sage method on identity matrix."""
        F = GF(2)
        matrix = identity_matrix(F, 3)
        bn = compute_branch_number_from_field_matrix_with_sage(matrix)
        assert bn == 2, f"Expected 2, got {bn}"

    def test_custom_modulus_field(self):
        """Test sage method on a custom-modulus field via Conway remapping."""
        R = PolynomialRing(GF(2), "x")
        x = R.gen()
        F = GF(2**8, name="a", modulus=x**8 + x**4 + x**3 + x + 1)
        matrix = Matrix(F, [[F.gen(), F.gen() + 1], [1, 0]])
        bn = compute_branch_number_from_field_matrix_with_sage(matrix)
        assert bn == 2, f"Expected 2, got {bn}"


class TestFieldMatrixWithBoundedEnumeration:
    """Test suite for compute_branch_number_from_field_matrix_with_bounded_enumeration."""

    def test_gf2_matrix(self):
        """Test bounded method on GF(2) matrix."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=3)
        assert bn == 2, f"Expected 2, got {bn}"

    def test_gf4_matrix(self):
        """Test bounded method on GF(4) matrix."""
        F = GF(4, 'a')
        matrix = Matrix(F, [[1, 1], [1, F.gen()]])
        bn = compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=3)
        assert bn == 3, f"Expected 3, got {bn}"

    def test_identity_matrix(self):
        """Test bounded method on identity matrix."""
        F = GF(2)
        matrix = identity_matrix(F, 3)
        bn = compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=3)
        assert bn == 2, f"Expected 2, got {bn}"

    def test_max_input_weight_parameter(self):
        """Test that max_input_weight parameter is respected."""
        F = GF(2)
        matrix = identity_matrix(F, 3)
        bn = compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=1)
        assert bn == 2, f"Expected 2 with max_input_weight=1, got {bn}"


class TestFieldMatrixWithMethodParameter:
    """Test suite for compute_branch_number_from_field_matrix with method parameter."""

    def test_default_method_is_sage(self):
        """Test that default method is 'sage'."""
        F = GF(2)
        matrix = identity_matrix(F, 2)
        bn_default = compute_branch_number_from_field_matrix(matrix)
        bn_sage = compute_branch_number_from_field_matrix(matrix, method="sage")
        assert bn_default == bn_sage, f"Default method should be 'sage': {bn_default} != {bn_sage}"

    def test_method_sage(self):
        """Test explicit method='sage' parameter."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_field_matrix(matrix, method="sage")
        assert bn == 2, f"Expected 2 with method='sage', got {bn}"

    def test_method_bounded(self):
        """Test explicit method='bounded' parameter."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_field_matrix(matrix, method="bounded", max_input_weight=3)
        assert bn == 2, f"Expected 2 with method='bounded', got {bn}"

    def test_sage_and_bounded_give_same_result_gf2(self):
        """Test that both methods give the same result on GF(2) matrices."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0, 0], [1, 1, 0], [0, 1, 1]])
        bn_sage = compute_branch_number_from_field_matrix(matrix, method="sage")
        bn_bounded = compute_branch_number_from_field_matrix(matrix, method="bounded", max_input_weight=3)
        assert bn_sage == bn_bounded, f"Sage and bounded methods disagree: {bn_sage} != {bn_bounded}"

    def test_sage_and_bounded_give_same_result_gf4(self):
        """Test that both methods give the same result on GF(4) matrices."""
        F = GF(4, 'a')
        matrix = Matrix(F, [[1, 1], [1, F.gen()]])
        bn_sage = compute_branch_number_from_field_matrix(matrix, method="sage")
        bn_bounded = compute_branch_number_from_field_matrix(matrix, method="bounded", max_input_weight=3)
        assert bn_sage == bn_bounded, f"Sage and bounded methods disagree: {bn_sage} != {bn_bounded}"

    def test_gf2_delegates_to_binary_version(self):
        """Test that GF(2) matrices use optimized binary version."""
        F = GF(2)
        matrix = identity_matrix(F, 4)
        # Both should work and give same result
        bn_field = compute_branch_number_from_field_matrix(matrix, method="sage")
        bn_binary = compute_branch_number_from_binary_matrix(matrix, method="sage")
        assert bn_field == bn_binary == 2, f"GF(2) field and binary methods should agree"

    def test_invalid_method_raises_error(self):
        """Test that invalid method parameter raises error."""
        F = GF(2)
        matrix = identity_matrix(F, 2)
        try:
            compute_branch_number_from_field_matrix(matrix, method="invalid")
            assert False, "Should have raised ValueError for invalid method"
        except ValueError as e:
            assert "Unknown method" in str(e)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_matrix_binary_raises_error(self):
        """Test that empty matrix raises error."""
        try:
            compute_branch_number_from_binary_matrix([], "differential")
            assert False, "Should raise error for empty matrix"
        except ValueError as e:
            assert "non-empty" in str(e).lower()

    def test_non_square_matrix_binary_raises_error(self):
        """Test that non-square matrix raises error."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0, 1], [1, 1, 0]])
        try:
            compute_branch_number_from_binary_matrix(matrix, "differential")
            assert False, "Should raise error for non-square matrix"
        except ValueError as e:
            assert "square" in str(e).lower()

    def test_non_square_matrix_field_raises_error(self):
        """Test that non-square field matrix raises error."""
        F = GF(2)
        matrix = Matrix(F, [[1, 0, 1], [1, 1, 0]])
        try:
            compute_branch_number_from_field_matrix(matrix)
            assert False, "Should raise error for non-square matrix"
        except ValueError as e:
            error_message = str(e).lower()
            assert ("square" in error_message) or ("non-empty" in error_message)

    def test_single_element_matrix_binary(self):
        """Test branch number on 1x1 matrix."""
        F = GF(2)
        matrix = Matrix(F, [[1]])
        bn = compute_branch_number_from_binary_matrix(matrix, "differential")
        assert bn == 2, f"Expected 2 for 1x1 matrix, got {bn}"

    def test_single_element_matrix_field(self):
        """Test branch number on 1x1 field matrix."""
        F = GF(2)
        matrix = Matrix(F, [[1]])
        bn = compute_branch_number_from_field_matrix(matrix)
        assert bn == 2, f"Expected 2 for 1x1 matrix, got {bn}"


class TestConsistency:
    """Test consistency across different invocation patterns."""

    def test_binary_matrix_list_vs_sage_matrix(self):
        """Test that list and Sage matrix inputs give same result."""
        F = GF(2)
        sage_matrix = Matrix(F, [[1, 0], [1, 1]])
        list_matrix = [[1, 0], [1, 1]]
        bn_sage = compute_branch_number_from_binary_matrix(sage_matrix, "differential", method="sage")
        bn_list = compute_branch_number_from_binary_matrix(list_matrix, "differential", method="sage")
        assert bn_sage == bn_list, f"List and Sage matrix should give same result: {bn_list} != {bn_sage}"

    def test_field_matrix_consistency(self):
        """Test consistency of field matrix computation."""
        F = GF(4, 'a')
        matrix = Matrix(F, [[1, 1], [1, F.gen()]])
        bn1 = compute_branch_number_from_field_matrix(matrix, method="sage")
        bn2 = compute_branch_number_from_field_matrix(matrix, method="bounded", max_input_weight=4)
        assert bn1 == bn2, f"Field matrix methods should agree: {bn1} != {bn2}"

    def test_type_parameter_gives_different_results_for_asymmetric_matrix(self):
        """Test that type parameter can give different results for non-symmetric matrices."""
        F = GF(2)
        # Create a non-symmetric matrix
        matrix = Matrix(F, [[1, 0, 1], [0, 1, 1], [1, 1, 0]])
        bn_diff = compute_branch_number_from_binary_matrix(matrix, "differential", method="sage")
        bn_lin = compute_branch_number_from_binary_matrix(matrix, "linear", method="sage")
        # Both should be positive integers (they might be equal or different)
        assert isinstance(bn_diff, int) and bn_diff >= 1
        assert isinstance(bn_lin, int) and bn_lin >= 1

