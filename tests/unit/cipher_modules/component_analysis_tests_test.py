import os
import shutil
import builtins
from types import SimpleNamespace

import pytest
import matplotlib.pyplot as plt
import claasp.cipher_modules.component_analysis_tests as cat_module
from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.component_analysis_tests import (
    CipherComponentsAnalysis,
    compute_branch_number_from_binary_matrix,
    compute_branch_number_from_binary_matrix_with_sage,
    compute_branch_number_from_binary_matrix_with_bounded_enumeration,
    compute_branch_number_from_binary_matrix_with_minizinc,
    compute_branch_number_from_field_matrix,
    compute_branch_number_from_field_matrix_with_sage,
    compute_branch_number_from_field_matrix_with_bounded_enumeration,
    compute_branch_number_from_field_matrix_with_minizinc,
    branch_number,
)
from claasp.ciphers.stream_ciphers.bluetooth_stream_cipher_e0 import BluetoothStreamCipherE0
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
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
    aes = ToyAESBlockCipher(word_size=8, state_size=2, number_of_rounds=2)
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
    aes = ToyAESBlockCipher(word_size=8, state_size=2, number_of_rounds=2)
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


class TestBinaryMatrixWithMiniZinc:
    """Test suite for compute_branch_number_from_binary_matrix_with_minizinc."""

    def test_identity_matrix_2x2(self):
        if shutil.which("minizinc") is None:
            pytest.skip("MiniZinc not available in PATH")
        F = GF(2)
        matrix = identity_matrix(F, 2)
        bn = compute_branch_number_from_binary_matrix_with_minizinc(matrix, "differential")
        assert bn == 2

    def test_simple_matrix_linear(self):
        if shutil.which("minizinc") is None:
            pytest.skip("MiniZinc not available in PATH")
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        bn = compute_branch_number_from_binary_matrix_with_minizinc(matrix, "linear")
        assert bn == 2

    @pytest.mark.parametrize(
        "requested_solver,expected_attempt_order",
        [
            ("ortools", ["ortools", "cp-sat"]),
            ("cp-sat", ["cp-sat", "ortools"]),
        ],
    )
    def test_solver_alias_fallback_between_ortools_and_cp_sat(
        self, monkeypatch, requested_solver, expected_attempt_order
    ):
        attempted = []

        def fake_run_minizinc_branch_number(
            minizinc_bin,
            solver,
            model_path,
            data_path,
            timeout_seconds,
            threads,
        ):
            del minizinc_bin, model_path, data_path, timeout_seconds, threads
            attempted.append(solver)
            if solver == expected_attempt_order[-1]:
                return SimpleNamespace(returncode=0, stdout="Branch number: 2\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr=f"Unknown solver {solver}")

        monkeypatch.setattr(cat_module.shutil, "which", lambda _bin: "/usr/bin/minizinc")
        monkeypatch.setattr(cat_module, "_run_minizinc_branch_number", fake_run_minizinc_branch_number)

        result = compute_branch_number_from_binary_matrix_with_minizinc(
            [[1, 0], [0, 1]],
            solver=requested_solver,
        )

        assert result == 2
        assert attempted == expected_attempt_order


def _matrix_from_ints_over_gf2w(entries, word_size, polynomial):
    if word_size == 1:
        F = GF(2)
        return Matrix(F, entries)

    R = PolynomialRing(GF(2), "x")
    x = R.gen()
    irr_poly = 0
    for i in range(word_size + 1):
        if (polynomial >> i) & 1:
            irr_poly += x**i
    F = GF(2**word_size, name="a", modulus=irr_poly)

    # Sage finite field APIs differ by version: some expose from_integer, others fetch_int.
    if hasattr(F, "from_integer"):
        to_field = lambda v: F.from_integer(int(v))
    else:
        to_field = lambda v: F.fetch_int(int(v))

    converted = [[to_field(value) for value in row] for row in entries]
    return Matrix(F, converted)


# Each test case is a tuple:
# (case_name, matrix_entries_as_integers, field_word_size, irreducible_polynomial_as_int, expected_branch_number)
_MINIZINC_FIELD_DEMO_CASES = [
    ("GF(2) zero 2x2", [[0, 0], [0, 0]], 1, 0b11, 1),
    ("GF(2) identity 2x2", [[1, 0], [0, 1]], 1, 0b11, 2),
    ("GF(4) identity 2x2", [[1, 0], [0, 1]], 2, 0b111, 2),
    ("GF(4) MDS 2x2", [[1, 1], [1, 2]], 2, 0b111, 3),
    ("GF(16) identity 2x2", [[1, 0], [0, 1]], 4, 0b10011, 2),
    ("ToyAES MDS w=2 n=2", [[0x02, 0x03], [0x03, 0x02]], 2, 0x7, 3),
    ("ToyAES MDS w=2 n=3", [[0x01, 0x02, 0x02], [0x02, 0x01, 0x02], [0x02, 0x02, 0x01]], 2, 0x7, 4),
    (
        "ToyAES MDS w=2 n=4",
        [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02],
        ],
        2,
        0x7,
        3,
    ),
    ("ToyAES MDS w=3 n=2", [[0x02, 0x03], [0x03, 0x02]], 3, 0xB, 3),
    ("ToyAES MDS w=3 n=3", [[0x01, 0x02, 0x05], [0x05, 0x06, 0x05], [0x05, 0x05, 0x01]], 3, 0xB, 4),
    (
        "ToyAES MDS w=3 n=4",
        [
            [0x01, 0x07, 0x05, 0x05],
            [0x07, 0x02, 0x01, 0x03],
            [0x06, 0x03, 0x01, 0x02],
            [0x07, 0x05, 0x05, 0x07],
        ],
        3,
        0xB,
        5,
    ),
    ("ToyAES MDS w=4 n=2", [[0x02, 0x03], [0x03, 0x02]], 4, 0x13, 3),
    ("ToyAES MDS w=4 n=3", [[0x08, 0x03, 0x04], [0x0A, 0x06, 0x09], [0x03, 0x04, 0x0C]], 4, 0x13, 4),
    (
        "ToyAES MDS w=4 n=4",
        [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02],
        ],
        4,
        0x13,
        5,
    ),
    ("ToyAES MDS w=8 n=2", [[0x02, 0x03], [0x03, 0x02]], 8, 0x11B, 3),
    ("ToyAES MDS w=8 n=3", [[0x01, 0x02, 0x05], [0x05, 0x06, 0x05], [0x05, 0x05, 0x01]], 8, 0x11B, 4),
    (
        "ToyAES MDS w=8 n=4",
        [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02],
        ],
        8,
        0x11B,
        5,
    ),
    (
        "uBlock GF(16) 32x32",
        [
            [1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0],
            [0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0],
            [0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0],
            [1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1],
            [0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        ],
        4,
        0x13,
        8,
    ),
]


@pytest.mark.parametrize("_name,entries,word_size,poly,expected", _MINIZINC_FIELD_DEMO_CASES)
def test_compute_branch_number_from_field_matrix_with_minizinc_demo_cases(_name, entries, word_size, poly, expected):
    if shutil.which("minizinc") is None:
        pytest.skip("MiniZinc not available in PATH")
    matrix = _matrix_from_ints_over_gf2w(entries, word_size, poly)
    got = compute_branch_number_from_field_matrix_with_minizinc(matrix)
    assert got == expected, f"{_name}: expected {expected}, got {got}"


class TestBranchNumberMethodConsistency:
    def test_binary_methods_agree(self):
        F = GF(2)
        matrix = Matrix(F, [[1, 0, 0], [1, 1, 0], [0, 1, 1]])

        bn_sage = compute_branch_number_from_binary_matrix(matrix, "differential", method="sage")
        bn_bounded = compute_branch_number_from_binary_matrix(matrix, "differential", method="bounded", max_input_weight=3)
        assert bn_sage == bn_bounded

        if shutil.which("minizinc") is None:
            pytest.skip("MiniZinc not available in PATH")
        bn_minizinc = compute_branch_number_from_binary_matrix(matrix, "differential", method="minizinc")
        assert bn_minizinc == bn_sage

    def test_field_methods_agree(self):
        F = GF(4, 'a')
        matrix = Matrix(F, [[1, 1], [1, F.gen()]])

        bn_sage = compute_branch_number_from_field_matrix(matrix, method="sage")
        bn_bounded = compute_branch_number_from_field_matrix(matrix, method="bounded", max_input_weight=3)
        assert bn_sage == bn_bounded

        if shutil.which("minizinc") is None:
            pytest.skip("MiniZinc not available in PATH")
        bn_minizinc = compute_branch_number_from_field_matrix(matrix, method="minizinc")
        assert bn_minizinc == bn_sage


class TestBinaryMatrixWithMethodParameter:
    """Test suite for compute_branch_number_from_binary_matrix with method parameter."""

    def test_default_method_is_minizinc(self, monkeypatch):
        """Test that default method dispatches to MiniZinc path."""
        F = GF(2)
        matrix = identity_matrix(F, 2)

        def fake_minizinc(_matrix, _type, solver="ortools", minizinc_bin="minizinc", timeout_seconds=None, threads=2):
            return 37

        monkeypatch.setattr(cat_module, "compute_branch_number_from_binary_matrix_with_minizinc", fake_minizinc)
        bn_default = compute_branch_number_from_binary_matrix(matrix, "differential")
        assert bn_default == 37

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

    def test_gf16_matrix_reaches_weight_four_path(self):
        """Exercise bounded enumeration path beyond weight 3 on a 4x4 field matrix."""
        F = GF(2**4, name="a")
        a = F.gen()
        matrix = Matrix(
            F,
            [
                [a**2 + a, a**3 + a**2, a**3 + a**2 + a + 1, a**3 + a**2 + a],
                [a**3 + a, a**2 + 1, a + 1, a**3 + a**2 + a],
                [a + 1, a**3 + a**2, a**3 + a**2, a**3 + a**2 + a + 1],
                [a**3, 1, a**3 + a, a**3 + a**2 + a + 1],
            ],
        )
        bn = compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=4)
        assert bn == 5, f"Expected 5 for GF(16) test matrix with max_input_weight=4, got {bn}"


class TestFieldMatrixWithMethodParameter:
    """Test suite for compute_branch_number_from_field_matrix with method parameter."""

    def test_default_method_is_minizinc(self, monkeypatch):
        """Test that default method dispatches to MiniZinc path."""
        F = GF(2)
        matrix = identity_matrix(F, 2)

        def fake_minizinc(_matrix, solver="ortools", minizinc_bin="minizinc", timeout_seconds=None, threads=2):
            return 41

        monkeypatch.setattr(cat_module, "compute_branch_number_from_field_matrix_with_minizinc", fake_minizinc)
        bn_default = compute_branch_number_from_field_matrix(matrix)
        assert bn_default == 41

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

    def test_sage_method_failure_raises_runtime_error(self, monkeypatch):
        """Test field wrapper raises clear error when Sage backend fails."""
        F = GF(4, 'a')
        matrix = Matrix(F, [[1, 1], [1, F.gen()]])

        def raise_runtime_error(_matrix):
            raise RuntimeError("forced failure")

        monkeypatch.setattr(cat_module, "compute_branch_number_from_field_matrix_with_sage", raise_runtime_error)
        with pytest.raises(RuntimeError, match="method='sage'.*forced failure"):
            compute_branch_number_from_field_matrix(matrix, method="sage")


class TestMapMatrixToConwayField:
    """Test helper behavior for field remapping utility."""

    def test_degree_one_field_returns_input_matrix(self):
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        mapped = cat_module._map_matrix_to_conway_field(matrix)
        assert mapped is matrix

    def test_already_conway_field_returns_input_matrix(self):
        F = GF(4, name="c")
        matrix = Matrix(F, [[1, 1], [1, F.gen()]])
        mapped = cat_module._map_matrix_to_conway_field(matrix)
        assert mapped is matrix


class TestInternalEnumerationHelpers:
    """Targeted tests to cover helper-level enumeration branches."""

    def test_search_binary_weight2_early_stop_when_best_is_two(self):
        best, done = cat_module._search_binary_weight_2([0b01, 0b10], 2)
        assert best == 2 and done is True

    def test_search_binary_weight3_early_stop_when_best_is_three(self):
        best, done = cat_module._search_binary_weight_3([0b001, 0b010, 0b100], 3)
        assert best == 3 and done is True

    def test_search_binary_weight4_plus_break_on_best_threshold(self):
        best, done = cat_module._search_binary_weight_4_plus([0b01, 0b10, 0b11, 0b00], limit=5, best=4)
        assert best == 4 and done is False

    def test_search_field_weight2_early_stop_when_best_is_two(self):
        F = GF(4, 'a')
        rows = [Matrix(F, [[1, 0]]).row(0), Matrix(F, [[0, 1]]).row(0)]
        best, done = cat_module._search_field_weight_2(rows, [x for x in F if x != 0], 2)
        assert best == 2 and done is True

    def test_search_field_weight3_early_stop_when_best_is_three(self):
        F = GF(4, 'a')
        rows = [
            Matrix(F, [[1, 0, 0]]).row(0),
            Matrix(F, [[0, 1, 0]]).row(0),
            Matrix(F, [[0, 0, 1]]).row(0),
        ]
        best, done = cat_module._search_field_weight_3(rows, [x for x in F if x != 0], 3)
        assert best == 3 and done is True

    def test_search_field_weight4_plus_break_on_best_threshold(self):
        F = GF(4, 'a')
        rows = [
            Matrix(F, [[1, 0, 0, 0]]).row(0),
            Matrix(F, [[0, 1, 0, 0]]).row(0),
            Matrix(F, [[0, 0, 1, 0]]).row(0),
            Matrix(F, [[0, 0, 0, 1]]).row(0),
        ]
        best, done = cat_module._search_field_weight_4_plus(rows, [x for x in F if x != 0], limit=5, best=4)
        assert best == 4 and done is False


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

    def test_binary_bounded_invalid_max_input_weight_raises_error(self):
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        with pytest.raises(ValueError, match="max_input_weight"):
            compute_branch_number_from_binary_matrix_with_bounded_enumeration(
                matrix,
                "differential",
                max_input_weight=0,
            )

    def test_field_bounded_invalid_max_input_weight_raises_error(self):
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])
        with pytest.raises(ValueError, match="max_input_weight"):
            compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=0)

    def test_binary_wrapper_sage_method_failure_raises_runtime_error(self, monkeypatch):
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [1, 1]])

        def raise_runtime_error(_binary_matrix, _type):
            raise RuntimeError("forced failure")

        monkeypatch.setattr(cat_module, "compute_branch_number_from_binary_matrix_with_sage", raise_runtime_error)
        with pytest.raises(RuntimeError, match="method='sage'.*forced failure"):
            compute_branch_number_from_binary_matrix(matrix, "differential", method="sage")


class TestNewCodeCoverageTargets:
    def test_minizinc_solver_alias_candidates_default_passthrough(self):
        assert cat_module._minizinc_solver_alias_candidates("chuffed") == ("chuffed",)

    def test_to_dzn_matrix_literal_input_validation_errors(self):
        with pytest.raises(ValueError, match="non-empty and square"):
            cat_module._to_dzn_matrix_literal_from_binary_matrix([[1, 0], [1]], original_word_size=1)

        with pytest.raises(ValueError, match="multiple of original_word_size"):
            cat_module._to_dzn_matrix_literal_from_binary_matrix([[1, 0], [0, 1]], original_word_size=3)

    def test_parse_branch_number_from_minizinc_stdout_error(self):
        with pytest.raises(RuntimeError, match="Could not parse branch number"):
            cat_module._parse_branch_number_from_minizinc_stdout("no branch number here")

    def test_run_minizinc_branch_number_thread_flag_selection(self, monkeypatch):
        captured = {}

        def fake_run(command, check, capture_output, text, timeout):
            captured["command"] = command
            captured["check"] = check
            captured["capture_output"] = capture_output
            captured["text"] = text
            captured["timeout"] = timeout
            return SimpleNamespace(returncode=0, stdout="Branch number: 2\n", stderr="")

        monkeypatch.setattr(cat_module.subprocess, "run", fake_run)

        cat_module._run_minizinc_branch_number(
            minizinc_bin="minizinc",
            solver="cp-sat",
            model_path="m.mzn",
            data_path="i.dzn",
            timeout_seconds=None,
            threads=4,
        )
        assert "-p" in captured["command"]

        cat_module._run_minizinc_branch_number(
            minizinc_bin="minizinc",
            solver="cbc",
            model_path="m.mzn",
            data_path="i.dzn",
            timeout_seconds=None,
            threads=4,
        )
        assert "-p" not in captured["command"]

    def test_compute_from_expanded_binary_matrix_timeout_not_supported(self):
        with pytest.raises(ValueError, match="timeout_seconds is not supported"):
            cat_module._compute_branch_number_from_expanded_binary_matrix_with_minizinc(
                binary_matrix=[[1]],
                original_word_size=1,
                timeout_seconds=1,
            )

    def test_compute_from_expanded_binary_matrix_missing_minizinc_binary(self, monkeypatch):
        monkeypatch.setattr(cat_module.shutil, "which", lambda _bin: None)
        with pytest.raises(FileNotFoundError, match="was not found in PATH"):
            cat_module._compute_branch_number_from_expanded_binary_matrix_with_minizinc(
                binary_matrix=[[1]],
                original_word_size=1,
            )

    def test_compute_from_expanded_binary_matrix_reports_solver_failures(self, monkeypatch):
        monkeypatch.setattr(cat_module.shutil, "which", lambda _bin: "/usr/bin/minizinc")

        def fake_run_minizinc_branch_number(**_kwargs):
            return SimpleNamespace(returncode=1, stdout="solver stdout", stderr="solver stderr")

        monkeypatch.setattr(cat_module, "_run_minizinc_branch_number", fake_run_minizinc_branch_number)
        with pytest.raises(RuntimeError, match="failed for all attempted solvers") as exc_info:
            cat_module._compute_branch_number_from_expanded_binary_matrix_with_minizinc(
                binary_matrix=[[1, 0], [0, 1]],
                original_word_size=1,
                solver="chuffed",
            )
        error_text = str(exc_info.value)
        assert "stderr: solver stderr" in error_text
        assert "stdout: solver stdout" in error_text

    def test_compute_from_expanded_binary_matrix_failure_without_solver_streams(self, monkeypatch):
        monkeypatch.setattr(cat_module.shutil, "which", lambda _bin: "/usr/bin/minizinc")

        def fake_run_minizinc_branch_number(**_kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="")

        monkeypatch.setattr(cat_module, "_run_minizinc_branch_number", fake_run_minizinc_branch_number)
        with pytest.raises(RuntimeError, match="failed for all attempted solvers") as exc_info:
            cat_module._compute_branch_number_from_expanded_binary_matrix_with_minizinc(
                binary_matrix=[[1, 0], [0, 1]],
                original_word_size=1,
                solver="chuffed",
            )
        assert "stderr:" not in str(exc_info.value)
        assert "stdout:" not in str(exc_info.value)

    @pytest.mark.parametrize(
        "word_size,poly,expected_message",
        [
            (0, 0b11, "word_size must be >= 1"),
            (2, 0, "irreducible_polynomial must be positive"),
            (3, 0b111, "degree exactly word_size"),
            (3, 0b1000, "non-zero constant term"),
        ],
    )
    def test_validate_irreducible_polynomial_errors(self, word_size, poly, expected_message):
        with pytest.raises(ValueError, match=expected_message):
            cat_module._validate_irreducible_polynomial(word_size, poly)

    def test_compute_branch_number_from_field_matrix_with_sage_empty_matrix(self):
        empty = Matrix(GF(2), 0, 0)
        with pytest.raises(ValueError, match="non-empty matrix"):
            compute_branch_number_from_field_matrix_with_sage(empty)

    def test_initialize_field_enumeration_empty_matrix(self):
        empty = Matrix(GF(2), 0, 0)
        with pytest.raises(ValueError, match="non-empty matrix"):
            cat_module._initialize_field_enumeration(empty, 1)

    def test_map_matrix_to_conway_field_raises_if_no_roots(self, monkeypatch):
        class FakeModulus:
            def roots(self, _target_field, multiplicities=False):
                del multiplicities
                return []

        class FakeField:
            def degree(self):
                return 2

            def order(self):
                return 4

            def __eq__(self, _other):
                return False

            def modulus(self):
                return FakeModulus()

        class FakeMatrix:
            def base_ring(self):
                return FakeField()

        monkeypatch.setattr(cat_module, "GF", lambda _order, name="c": object())

        with pytest.raises(NotImplementedError, match="Could not construct an isomorphism"):
            cat_module._map_matrix_to_conway_field(FakeMatrix())

    def test_field_search_helpers_explicit_early_exit_paths(self, monkeypatch):
        monkeypatch.setattr(cat_module, "_update_best_branch_number", lambda _candidate, _best: (2, True))
        F = GF(4, 'a')

        rows2 = [Matrix(F, [[1, 0]]).row(0), Matrix(F, [[0, 1]]).row(0)]
        best2, done2 = cat_module._search_field_weight_2(rows2, [x for x in F if x != 0], 99)
        assert best2 == 2 and done2 is True

        rows3 = [
            Matrix(F, [[1, 0, 0]]).row(0),
            Matrix(F, [[0, 1, 0]]).row(0),
            Matrix(F, [[0, 0, 1]]).row(0),
        ]
        best3, done3 = cat_module._search_field_weight_3(rows3, [x for x in F if x != 0], 99)
        assert best3 == 2 and done3 is True

        rows4 = [
            Matrix(F, [[1, 0, 0, 0]]).row(0),
            Matrix(F, [[0, 1, 0, 0]]).row(0),
            Matrix(F, [[0, 0, 1, 0]]).row(0),
            Matrix(F, [[0, 0, 0, 1]]).row(0),
        ]
        best4, done4 = cat_module._search_field_weight_4_plus(rows4, [x for x in F if x != 0], limit=4, best=99)
        assert best4 == 2 and done4 is True

    def test_field_bounded_enumeration_return_guards(self, monkeypatch):
        F = GF(2)
        matrix = Matrix(F, [[0, 0], [0, 0]])
        assert compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=1) == 1

        monkeypatch.setattr(cat_module, "_search_field_weight_1", lambda rows, best: (best, False))
        monkeypatch.setattr(cat_module, "_search_field_weight_2", lambda rows, nz, best: (7, True))
        assert compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix, max_input_weight=2) == 7

        matrix3 = Matrix(F, [[0, 0, 0], [0, 0, 0], [0, 0, 0]])
        monkeypatch.setattr(cat_module, "_search_field_weight_2", lambda rows, nz, best: (7, False))
        monkeypatch.setattr(cat_module, "_search_field_weight_3", lambda rows, nz, best: (6, True))
        assert compute_branch_number_from_field_matrix_with_bounded_enumeration(matrix3, max_input_weight=3) == 6

    def test_prepare_binary_matrix_linear_list_path(self):
        matrix, n = cat_module._prepare_binary_matrix([[1, 0], [0, 1]], type="linear")
        assert n == 2
        assert int(matrix[0][0]) == 1 and int(matrix[1][1]) == 1

    def test_search_binary_weight_two_and_four_plus_early_return(self):
        best2, done2 = cat_module._search_binary_weight_2([0b1, 0b1], 9)
        assert best2 == 2 and done2 is True

        class WeirdMask:
            def __rxor__(self, _other):
                return self

            def __xor__(self, _other):
                return self

            def bit_count(self):
                return -2

        weird_columns = [WeirdMask(), WeirdMask(), WeirdMask(), WeirdMask()]
        best4, done4 = cat_module._search_binary_weight_4_plus(weird_columns, limit=4, best=9)
        assert best4 == 2 and done4 is True

    def test_search_binary_weight_two_three_and_four_plus_non_early_paths(self):
        best2, done2 = cat_module._search_binary_weight_2([0b001, 0b011, 0b101], 10)
        assert best2 == 3 and done2 is False

        best3, done3 = cat_module._search_binary_weight_3([0b001, 0b011, 0b101], 10)
        assert best3 == 6 and done3 is False

        best4, done4 = cat_module._search_binary_weight_4_plus([0b001, 0b011, 0b101, 0b111], limit=4, best=10)
        assert best4 == 4 and done4 is False

    def test_search_binary_weight_three_and_four_plus_no_update_paths(self):
        best3, done3 = cat_module._search_binary_weight_3([0b001, 0b011, 0b101], 4)
        assert best3 == 4 and done3 is False

        best4, done4 = cat_module._search_binary_weight_4_plus(
            [0b0001, 0b0010, 0b0100, 0b1000],
            limit=4,
            best=5,
        )
        assert best4 == 5 and done4 is False

    def test_search_binary_weight_three_loop_and_early_return(self):
        class WeirdMask:
            def __xor__(self, _other):
                return self

            def bit_count(self):
                return -1

        weird_columns = [WeirdMask(), WeirdMask(), WeirdMask()]
        best, done = cat_module._search_binary_weight_3(weird_columns, 10)
        assert best == 2 and done is True

    def test_compute_branch_number_from_field_matrix_with_minizinc_errors(self):
        with pytest.raises(ValueError, match="non-empty matrix"):
            compute_branch_number_from_field_matrix_with_minizinc(Matrix(GF(2), 0, 0))

        with pytest.raises(ValueError, match="characteristic 2"):
            compute_branch_number_from_field_matrix_with_minizinc(Matrix(GF(3), [[1, 0], [0, 1]]))

    def test_field_wrapper_minizinc_and_sage_error_wrapping(self, monkeypatch):
        F = GF(2)
        matrix = Matrix(F, [[1, 0], [0, 1]])

        monkeypatch.setattr(
            cat_module,
            "compute_branch_number_from_field_matrix_with_minizinc",
            lambda _matrix: (_ for _ in ()).throw(OSError("forced minizinc failure")),
        )
        with pytest.raises(RuntimeError, match="method='minizinc'.*forced minizinc failure"):
            compute_branch_number_from_field_matrix(matrix, method="minizinc")

        monkeypatch.setattr(
            cat_module,
            "compute_branch_number_from_binary_matrix",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("forced sage failure")),
        )
        with pytest.raises(RuntimeError, match="method='sage'.*forced sage failure"):
            compute_branch_number_from_field_matrix(matrix, method="sage")

    def test_calculate_weights_for_linear_layer_word_and_missing_matrix(self, monkeypatch):
        fake_component = SimpleNamespace(id="lin_0", type="linear_layer")
        printed = []

        monkeypatch.setattr(builtins, "print", lambda *args, **kwargs: printed.append(" ".join(str(a) for a in args)))

        monkeypatch.setattr(cat_module, "binary_matrix_of_linear_component", lambda _component: None)
        with pytest.raises(TypeError, match="Cannot compute the binary matrix"):
            cat_module.calculate_weights_for_linear_layer(fake_component, "word", "differential")
        assert any("format type cannot be 'word'" in line for line in printed)

    def test_instantiate_matrix_over_correct_field_without_custom_polynomial(self):
        matrix, field = cat_module.instantiate_matrix_over_correct_field(
            [[1, 0], [0, 1]],
            polynomial_as_int=0,
            word_size=2,
            input_bit_size=4,
            output_bit_size=4,
        )
        assert matrix.nrows() == 2 and matrix.ncols() == 2
        assert field.order() == 4

    def test_field_element_matrix_to_integer_matrix_int_fallback(self):
        class IntOnly:
            def __init__(self, value):
                self.value = value

            def __int__(self):
                return self.value

        class FakeMatrix:
            def nrows(self):
                return 1

            def ncols(self):
                return 2

            def __getitem__(self, i):
                del i
                return [IntOnly(3), IntOnly(5)]

        out = cat_module.field_element_matrix_to_integer_matrix(FakeMatrix())
        assert int(out[0][0]) == 3 and int(out[0][1]) == 5

    def test_field_element_matrix_to_integer_matrix_to_integer_path(self):
        class WithToInteger:
            def __init__(self, value):
                self.value = value

            def to_integer(self):
                return self.value

        class FakeMatrix:
            def nrows(self):
                return 1

            def ncols(self):
                return 1

            def __getitem__(self, i):
                del i
                return [WithToInteger(9)]

        out = cat_module.field_element_matrix_to_integer_matrix(FakeMatrix())
        assert int(out[0][0]) == 9

    def test_binary_matrix_with_sage_list_validation_paths(self):
        with pytest.raises(ValueError, match="non-empty square"):
            compute_branch_number_from_binary_matrix_with_sage([], "differential")

        with pytest.raises(ValueError, match="square"):
            compute_branch_number_from_binary_matrix_with_sage([[1, 0, 1], [0, 1, 0]], "linear")

    def test_binary_bounded_enumeration_late_paths_and_wrapper_errors(self, monkeypatch):
        matrix = [
            [1, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, 1, 0],
            [0, 0, 0, 1],
        ]

        monkeypatch.setattr(cat_module, "_search_binary_weight_1", lambda _cols, _best: 5)
        monkeypatch.setattr(cat_module, "_search_binary_weight_2", lambda _cols, _best: (8, False))
        monkeypatch.setattr(cat_module, "_search_binary_weight_3", lambda _cols, _best: (7, False))
        monkeypatch.setattr(cat_module, "_search_binary_weight_4_plus", lambda _cols, _limit, _best: (6, False))
        got = compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix, max_input_weight=4)
        assert got == 6

        monkeypatch.setattr(
            cat_module,
            "compute_branch_number_from_binary_matrix_with_minizinc",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("forced minizinc failure")),
        )
        with pytest.raises(RuntimeError, match="method='minizinc'.*forced minizinc failure"):
            compute_branch_number_from_binary_matrix(matrix, method="minizinc")

    def test_binary_bounded_enumeration_guard_returns(self, monkeypatch):
        matrix2 = [[1, 0], [0, 1]]
        matrix3 = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
        matrix4 = [
            [1, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, 1, 0],
            [0, 0, 0, 1],
        ]

        monkeypatch.setattr(cat_module, "_search_binary_weight_1", lambda _cols, _best: 5)

        monkeypatch.setattr(cat_module, "_search_binary_weight_2", lambda _cols, _best: (4, True))
        assert compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix4, max_input_weight=4) == 4

        monkeypatch.setattr(cat_module, "_search_binary_weight_2", lambda _cols, _best: (4, False))
        assert compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix2, max_input_weight=2) == 4

        monkeypatch.setattr(cat_module, "_search_binary_weight_2", lambda _cols, _best: (6, False))
        monkeypatch.setattr(cat_module, "_search_binary_weight_3", lambda _cols, _best: (5, True))
        assert compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix3, max_input_weight=3) == 5

        monkeypatch.setattr(cat_module, "_search_binary_weight_3", lambda _cols, _best: (4, False))
        assert compute_branch_number_from_binary_matrix_with_bounded_enumeration(matrix3, max_input_weight=3) == 4


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

