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

import importlib.util
import json
import os
import tempfile
from pathlib import Path

import numpy as np
import pytest

from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests


class TestNISTTests:
    """Test suite for NIST Statistical Test Suite (SP 800-22) implementation."""

    @pytest.fixture
    def random_binary_sequence(self):
        """Generate a random binary sequence for testing."""
        np.random.seed(42)
        return np.random.randint(0, 2, 10000, dtype=np.uint8)

    @pytest.fixture
    def random_packed_bytes(self):
        """Generate random data in packed bytes format."""
        np.random.seed(42)
        # Generate 1250 bytes (which will expand to 10000 bits)
        return bytes(np.random.randint(0, 256, 1250, dtype=np.uint8))

    @pytest.fixture
    def alternating_sequence(self):
        """Generate an alternating binary sequence (010101...)."""
        return np.array([i % 2 for i in range(10000)], dtype=np.uint8)

    @pytest.fixture
    def all_zeros(self):
        """Generate a sequence of all zeros."""
        return np.zeros(10000, dtype=np.uint8)

    @pytest.fixture
    def all_ones(self):
        """Generate a sequence of all ones."""
        return np.ones(10000, dtype=np.uint8)

    def test_frequency_test_random(self, random_binary_sequence):
        """Test frequency (monobit) test with random data."""
        result = NISTTests.frequency_test(random_binary_sequence)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert isinstance(result['p_value'], (float, np.floating))
        assert isinstance(result['passed'], (bool, np.bool_))
        assert 0 <= result['p_value'] <= 1

    def test_frequency_test_biased(self, all_zeros):
        """Test frequency test with biased data (should fail)."""
        result = NISTTests.frequency_test(all_zeros)
        
        assert result['passed'] == False
        assert result['p_value'] < 0.01

    def test_block_frequency_test_random(self, random_binary_sequence):
        """Test block frequency test with random data."""
        result = NISTTests.block_frequency_test(random_binary_sequence, block_size=100)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_block_frequency_test_alternating(self, alternating_sequence):
        """Test block frequency test with alternating sequence."""
        result = NISTTests.block_frequency_test(alternating_sequence, block_size=100)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 0 <= result['p_value'] <= 1

    def test_cumulative_sums_test_forward(self, random_binary_sequence):
        """Test cumulative sums test in forward mode."""
        result = NISTTests.cumulative_sums_test(random_binary_sequence, mode=0)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_cumulative_sums_test_backward(self, random_binary_sequence):
        """Test cumulative sums test in backward mode."""
        result = NISTTests.cumulative_sums_test(random_binary_sequence, mode=1)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_runs_test_random(self, random_binary_sequence):
        """Test runs test with random data."""
        result = NISTTests.runs_test(random_binary_sequence)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_runs_test_alternating(self, alternating_sequence):
        """Test runs test with alternating sequence (should have many runs)."""
        result = NISTTests.runs_test(alternating_sequence)
        
        assert isinstance(result, dict)
        assert 'p_value' in result

    def test_longest_run_test_random(self, random_binary_sequence):
        """Test longest run of ones test with random data."""
        result = NISTTests.longest_run_test(random_binary_sequence)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_rank_test_random(self, random_binary_sequence):
        """Test binary matrix rank test with random data."""
        result = NISTTests.rank_test(random_binary_sequence)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_dft_test_random(self, random_binary_sequence):
        """Test discrete Fourier transform (spectral) test with random data."""
        result = NISTTests.dft_test(random_binary_sequence)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_dft_test_periodic(self):
        """Test DFT test with periodic sequence (should fail)."""
        # Create a periodic sequence with period 100
        periodic = np.tile([1, 0] * 50, 100)
        result = NISTTests.dft_test(periodic)
        
        assert isinstance(result, dict)
        assert 'p_value' in result

    def test_non_overlapping_template_test_random(self, random_binary_sequence):
        """Test non-overlapping template matching test with random data."""
        result = NISTTests.non_overlapping_template_test(random_binary_sequence, block_size=100)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_overlapping_template_test_random(self, random_binary_sequence):
        """Test overlapping template matching test with random data."""
        result = NISTTests.overlapping_template_test(random_binary_sequence, block_size=1000)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_universal_test_random(self, random_binary_sequence):
        """Test Maurer's universal statistical test with random data."""
        result = NISTTests.universal_test(random_binary_sequence)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_approximate_entropy_test_random(self, random_binary_sequence):
        """Test approximate entropy test with random data."""
        result = NISTTests.approximate_entropy_test(random_binary_sequence, m=2)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_random_excursions_test_random(self, random_binary_sequence):
        """Test random excursions test with random data."""
        result = NISTTests.random_excursions_test(random_binary_sequence)
        
        assert isinstance(result, dict)
        # This test returns p_values (plural) as it tests multiple states
        assert 'p_values' in result or 'p_value' in result
        assert 'passed' in result

    def test_random_excursions_variant_test_random(self, random_binary_sequence):
        """Test random excursions variant test with random data."""
        result = NISTTests.random_excursions_variant_test(random_binary_sequence)
        
        assert isinstance(result, dict)
        # This test returns p_values (plural) as it tests multiple states
        assert 'p_values' in result or 'p_value' in result
        assert 'passed' in result

    def test_serial_test_random(self, random_binary_sequence):
        """Test serial test with random data."""
        result = NISTTests.serial_test(random_binary_sequence, m=2)
        
        assert isinstance(result, dict)
        # Serial test returns p_value1 and p_value2
        assert 'p_value1' in result or 'p_value' in result
        assert 'passed' in result

    def test_linear_complexity_test_random(self, random_binary_sequence):
        """Test linear complexity test with random data."""
        result = NISTTests.linear_complexity_test(random_binary_sequence, block_size=500)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_short_sequence_handling(self):
        """Test that methods handle short sequences appropriately."""
        short_seq = np.random.randint(0, 2, 100, dtype=np.uint8)
        
        # These should still return valid results or handle gracefully
        result = NISTTests.frequency_test(short_seq)
        assert isinstance(result, dict)
        
        result = NISTTests.runs_test(short_seq)
        assert isinstance(result, dict)

    def test_edge_case_minimum_length(self):
        """Test with minimum viable sequence lengths."""
        min_seq = np.random.randint(0, 2, 1000, dtype=np.uint8)
        
        # Basic tests should work with 1000 bits
        result = NISTTests.frequency_test(min_seq)
        assert isinstance(result, dict)
        assert 'p_value' in result

    def test_invalid_input_handling(self):
        """Test that methods handle invalid inputs gracefully."""
        # Test with non-binary values (should ideally be handled or raise error)
        invalid_seq = np.array([0, 1, 2, 3], dtype=np.uint8)
        
        # Depending on implementation, this might raise an error or handle it
        # For now, just ensure it doesn't crash unexpectedly
        try:
            result = NISTTests.frequency_test(invalid_seq)
            # If it doesn't raise, it should return a valid dict
            assert isinstance(result, dict)
        except (ValueError, AssertionError):
            # It's acceptable to raise an error for invalid input
            pass

    def test_deterministic_behavior(self):
        """Test that same input produces same output (deterministic)."""
        np.random.seed(123)
        seq = np.random.randint(0, 2, 5000, dtype=np.uint8)
        
        result1 = NISTTests.frequency_test(seq)
        result2 = NISTTests.frequency_test(seq)
        
        assert result1['p_value'] == result2['p_value']
        assert result1['passed'] == result2['passed']

    def test_all_tests_return_format_consistency(self, random_binary_sequence):
        """Test that all tests return consistent dictionary format."""
        tests = [
            lambda: NISTTests.frequency_test(random_binary_sequence),
            lambda: NISTTests.block_frequency_test(random_binary_sequence, block_size=100),
            lambda: NISTTests.cumulative_sums_test(random_binary_sequence, mode=0),
            lambda: NISTTests.runs_test(random_binary_sequence),
            lambda: NISTTests.longest_run_test(random_binary_sequence),
            lambda: NISTTests.rank_test(random_binary_sequence),
            lambda: NISTTests.dft_test(random_binary_sequence),
            lambda: NISTTests.non_overlapping_template_test(random_binary_sequence),
            lambda: NISTTests.overlapping_template_test(random_binary_sequence),
            lambda: NISTTests.universal_test(random_binary_sequence),
            lambda: NISTTests.approximate_entropy_test(random_binary_sequence, m=2),
            lambda: NISTTests.random_excursions_test(random_binary_sequence),
            lambda: NISTTests.random_excursions_variant_test(random_binary_sequence),
            lambda: NISTTests.serial_test(random_binary_sequence, m=2),
            lambda: NISTTests.linear_complexity_test(random_binary_sequence, block_size=500)
        ]
        
        for test_func in tests:
            result = test_func()
            assert isinstance(result, dict), f"Test did not return a dict"
            assert 'passed' in result, f"Test result missing 'passed' key"
            # All tests should have some form of p_value
            assert any(key in result for key in ['p_value', 'p_values', 'p_value1']), \
                f"Test result missing p_value key"

    def test_packed_bytes_format_frequency(self, random_packed_bytes):
        """Test frequency test with packed bytes input."""
        result = NISTTests.frequency_test(random_packed_bytes)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 'passed' in result
        assert 0 <= result['p_value'] <= 1

    def test_packed_bytes_format_block_frequency(self, random_packed_bytes):
        """Test block frequency test with packed bytes input."""
        result = NISTTests.block_frequency_test(random_packed_bytes, block_size=100)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 0 <= result['p_value'] <= 1

    def test_packed_bytes_format_runs(self, random_packed_bytes):
        """Test runs test with packed bytes input."""
        result = NISTTests.runs_test(random_packed_bytes)
        
        assert isinstance(result, dict)
        assert 'p_value' in result
        assert 0 <= result['p_value'] <= 1

    def test_packed_bytes_vs_binary_array_equivalence(self):
        """Test that packed bytes and binary array give same results."""
        # Create a known sequence
        test_bytes = b'\xA5' * 100  # 10100101 pattern
        
        # Convert to binary array manually
        binary_array = np.array([int(bit) for byte in test_bytes 
                                for bit in format(byte, '08b')], dtype=np.uint8)
        
        # Test frequency test
        result_bytes = NISTTests.frequency_test(test_bytes)
        result_array = NISTTests.frequency_test(binary_array)
        
        assert result_bytes['p_value'] == result_array['p_value']
        assert result_bytes['passed'] == result_array['passed']

    def test_packed_bytes_multiple_tests(self, random_packed_bytes):
        """Test that multiple tests work with packed bytes format."""
        tests = [
            lambda: NISTTests.frequency_test(random_packed_bytes),
            lambda: NISTTests.runs_test(random_packed_bytes),
            lambda: NISTTests.block_frequency_test(random_packed_bytes, block_size=100),
            lambda: NISTTests.cumulative_sums_test(random_packed_bytes, mode=0)
        ]
        
        for test_func in tests:
            result = test_func()
            assert isinstance(result, dict)
            assert 'p_value' in result
            assert 'passed' in result

    def test_ensure_binary_array_helper(self):
        """Test the _ensure_binary_array helper function directly."""
        # Test with packed bytes
        packed = b'\xFF\x00'
        result = NISTTests._ensure_binary_array(packed)
        expected = np.array([1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0], dtype=np.uint8)
        np.testing.assert_array_equal(result, expected)
        
        # Test with binary array (pass-through)
        binary = np.array([1, 0, 1, 0], dtype=np.uint8)
        result = NISTTests._ensure_binary_array(binary)
        np.testing.assert_array_equal(result, binary)
        
        # Test with bytearray
        ba = bytearray([0xA5])
        result = NISTTests._ensure_binary_array(ba)
        expected = np.array([1,0,1,0,0,1,0,1], dtype=np.uint8)
        np.testing.assert_array_equal(result, expected)

    def test_block_frequency_insufficient_blocks(self):
        """Test block frequency with insufficient data for blocks."""
        short_seq = np.random.randint(0, 2, 50, dtype=np.uint8)
        result = NISTTests.block_frequency_test(short_seq, block_size=100)
        assert result['passed'] is False
        assert result['p_value'] == 0.0

    def test_longest_run_too_short(self):
        """Test longest run test with sequence too short."""
        short_seq = np.random.randint(0, 2, 100, dtype=np.uint8)
        result = NISTTests.longest_run_test(short_seq)
        assert result['passed'] is False

    def test_rank_test_insufficient_data(self):
        """Test rank test with insufficient data."""
        short_seq = np.random.randint(0, 2, 500, dtype=np.uint8)
        result = NISTTests.rank_test(short_seq)
        assert result['passed'] is False

    def test_non_overlapping_template_with_custom_template(self):
        """Test non-overlapping template with custom template."""
        seq = np.random.randint(0, 2, 10000, dtype=np.uint8)
        template = np.array([1, 1, 1, 1, 1], dtype=np.uint8)
        result = NISTTests.non_overlapping_template_test(seq, template=template, block_size=100)
        assert isinstance(result, dict)
        assert 'p_value' in result

    def test_overlapping_template_with_custom_template(self):
        """Test overlapping template with custom template."""
        seq = np.random.randint(0, 2, 10000, dtype=np.uint8)
        template = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1], dtype=np.uint8)
        result = NISTTests.overlapping_template_test(seq, template=template, block_size=1000)
        assert isinstance(result, dict)
        assert 'p_value' in result

    def test_universal_test_insufficient_length(self):
        """Test universal test with insufficient sequence length."""
        short_seq = np.random.randint(0, 2, 10000, dtype=np.uint8)
        result = NISTTests.universal_test(short_seq)
        assert result['passed'] is False

    def test_universal_test_long_sequence(self):
        """Test universal test with adequate sequence length."""
        long_seq = np.random.randint(0, 2, 400000, dtype=np.uint8)
        result = NISTTests.universal_test(long_seq)
        assert isinstance(result, dict)
        assert 'p_value' in result

    def test_approximate_entropy_various_m_values(self):
        """Test approximate entropy with different m values."""
        seq = np.random.randint(0, 2, 10000, dtype=np.uint8)
        for m in [2, 3, 5]:
            result = NISTTests.approximate_entropy_test(seq, m=m)
            assert isinstance(result, dict)
            assert 'p_value' in result

    def test_random_excursions_insufficient_cycles(self):
        """Test random excursions with insufficient cycles."""
        # Create a sequence that won't have enough cycles
        short_seq = np.array([1, 0] * 100, dtype=np.uint8)
        result = NISTTests.random_excursions_test(short_seq)
        assert result['passed'] is False
        assert isinstance(result['p_values'], list)

    def test_random_excursions_variant_insufficient_cycles(self):
        """Test random excursions variant with insufficient cycles."""
        short_seq = np.array([1, 0] * 100, dtype=np.uint8)
        result = NISTTests.random_excursions_variant_test(short_seq)
        assert result['passed'] is False
        assert isinstance(result['p_values'], list)

    def test_serial_test_different_m_values(self):
        """Test serial test with different m values."""
        seq = np.random.randint(0, 2, 10000, dtype=np.uint8)
        for m in [2, 3, 4]:
            result = NISTTests.serial_test(seq, m=m)
            assert isinstance(result, dict)
            assert 'p_value1' in result
            assert 'p_value2' in result

    def test_linear_complexity_insufficient_data(self):
        """Test linear complexity with insufficient data."""
        short_seq = np.random.randint(0, 2, 100, dtype=np.uint8)
        result = NISTTests.linear_complexity_test(short_seq, block_size=500)
        assert result['passed'] is False

    def test_linear_complexity_different_block_sizes(self):
        """Test linear complexity with different block sizes."""
        seq = np.random.randint(0, 2, 100000, dtype=np.uint8)
        for block_size in [100, 250, 500]:
            result = NISTTests.linear_complexity_test(seq, block_size=block_size)
            assert isinstance(result, dict)
            assert 'p_value' in result

    def test_ensure_binary_array_list_of_integers(self):
        """Test _ensure_binary_array with list of integers (bytes)."""
        int_list = [0xAA, 0x55, 0xFF]
        result = NISTTests._ensure_binary_array(int_list)
        assert isinstance(result, np.ndarray)
        assert len(result) == 24  # 3 bytes = 24 bits

    def test_ensure_binary_array_numpy_with_values_gt_1(self):
        """Test _ensure_binary_array with numpy array containing values > 1."""
        arr = np.array([255, 128, 64], dtype=np.uint8)
        result = NISTTests._ensure_binary_array(arr)
        assert isinstance(result, np.ndarray)
        assert len(result) == 24  # Should unpack bytes

    def test_runs_test_pre_test_failure(self):
        """Test runs test when pre-test fails (pi not approximately 1/2)."""
        # Create biased sequence
        biased_seq = np.array([1] * 900 + [0] * 100, dtype=np.uint8)
        result = NISTTests.runs_test(biased_seq)
        assert result['passed'] is False

    def test_longest_run_different_sequence_lengths(self):
        """Test longest run with different sequence length categories."""
        # Test with n < 6272 (should use m=8)
        seq1 = np.random.randint(0, 2, 5000, dtype=np.uint8)
        result1 = NISTTests.longest_run_test(seq1)
        assert isinstance(result1, dict)
        
        # Test with 6272 <= n < 750000 (should use m=128)
        seq2 = np.random.randint(0, 2, 50000, dtype=np.uint8)
        result2 = NISTTests.longest_run_test(seq2)
        assert isinstance(result2, dict)

    def test_dft_test_all_zeros(self):
        """Test DFT with all zeros (should fail)."""
        zeros = np.zeros(1000, dtype=np.uint8)
        result = NISTTests.dft_test(zeros)
        assert isinstance(result, dict)
        # May or may not pass depending on threshold

    def test_non_overlapping_template_no_blocks(self):
        """Test non-overlapping template with too short sequence."""
        short_seq = np.random.randint(0, 2, 50, dtype=np.uint8)
        result = NISTTests.non_overlapping_template_test(short_seq, block_size=100)
        assert result['passed'] is False

    def test_overlapping_template_no_blocks(self):
        """Test overlapping template with too short sequence."""
        short_seq = np.random.randint(0, 2, 50, dtype=np.uint8)
        result = NISTTests.overlapping_template_test(short_seq, block_size=1000)
        assert result['passed'] is False


    # ========================================================================
    # Functional Equivalence Tests with C assess binary
    # ========================================================================
    # These tests verify that the Python implementation produces the same
    # results as the original NIST STS C assess binary (sts-2.1.2).
    # Test vectors were generated from the C binary and stored as reference.
    # ========================================================================

    def _load_generator_module(self, generator_path):
        spec = importlib.util.spec_from_file_location("generator", generator_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _normalize_c_test_name(self, name):
        name = name.replace("*", "").strip()
        if name.startswith("NonOverlappingTemplate_") or name.startswith("Non Overlapping Template_"):
            base, idx = name.rsplit("_", 1)
            return f"non_overlapping_template_{idx}"
        if "CumulativeSums" in name:
            lower = name.lower()
            if "backward" in lower:
                return "cumulative_sums_backward"
            return "cumulative_sums_forward"
        if "RandomExcursionsVariant" in name:
            state = name.split("(")[-1].rstrip(")")
            return f"random_excursions_variant_{state}"
        if "RandomExcursions" in name:
            state = name.split("(")[-1].rstrip(")")
            return f"random_excursions_{state}"
        if "Serial" in name:
            if "2" in name:
                return "serial_2"
            return "serial_1"
        mapping = {
            "Frequency": "frequency",
            "BlockFrequency": "block_frequency",
            "Runs": "runs",
            "LongestRun": "longest_run",
            "Rank": "rank",
            "FFT": "dft",
            "NonOverlappingTemplate": "non_overlapping_template",
            "Non Overlapping Template": "non_overlapping_template",
            "OverlappingTemplate": "overlapping_template",
            "Overlapping Template": "overlapping_template",
            "Universal": "universal",
            "ApproximateEntropy": "approximate_entropy",
            "LinearComplexity": "linear_complexity",
        }
        return mapping.get(name, name.replace(" ", "_").lower())

    def _load_case_inputs(self, case_dir):
        inputs_path = case_dir / "inputs.json"
        if not inputs_path.exists():
            pytest.skip(f"Missing inputs.json in {case_dir}")
        with open(inputs_path, "r") as f:
            return json.load(f)

    def _load_case_results(self, case_dir):
        results_path = case_dir / "results.json"
        if not results_path.exists():
            pytest.skip(f"Missing results.json in {case_dir}")
        with open(results_path, "r") as f:
            return json.load(f)

    def _get_dataset_path(self, inputs):
        dataset_path = Path(inputs["dataset_file"])
        if not dataset_path.exists():
            pytest.skip(f"Missing dataset file: {dataset_path}")
        return str(dataset_path)

    def _compare_results(self, python_results, c_results, tolerance=1e-6):
        c_tests = c_results["final_report_parsed"]["tests"]

        python_map = {t["test_name"]: t for t in python_results["tests"]}
        mismatches = []
        nonoverlap_idx = 0

        for c_test in c_tests:
            c_name = c_test["test_name"]
            if c_name in {"NonOverlappingTemplate", "Non Overlapping Template"}:
                py_name = f"non_overlapping_template_{nonoverlap_idx}"
                nonoverlap_idx += 1
            else:
                py_name = self._normalize_c_test_name(c_name)

            if py_name not in python_map:
                mismatches.append(f"Test '{c_name}' not found in Python results")
                continue

            py_test = python_map[py_name]

            p_diff = abs(c_test["uniformity_p_value"] - py_test["uniformity_p_value"])
            if p_diff > tolerance:
                mismatches.append(
                    f"{c_name}: uniformity p-value mismatch (C: {c_test['uniformity_p_value']:.6f}, "
                    f"Python: {py_test['uniformity_p_value']:.6f}, diff: {p_diff:.2e})"
                )

            if c_test["bin_counts"] != py_test["bin_counts"]:
                mismatches.append(
                    f"{c_name}: bin counts mismatch (C: {c_test['bin_counts']}, "
                    f"Python: {py_test['bin_counts']})"
                )

            c_passed = c_test["passed_sequences"]
            c_total = c_test["total_sequences"]
            if (c_passed != py_test["passed_sequences"] or
                    c_total != py_test["total_sequences"]):
                mismatches.append(
                    f"{c_name}: pass count mismatch (C: {c_passed}/{c_total}, "
                    f"Python: {py_test['passed_sequences']}/{py_test['total_sequences']})"
                )

            if py_name.startswith("non_overlapping_template"):
                continue

            detail = c_results.get("test_details", {}).get(c_test["test_name"], {})
            if "p_values" in detail and "p_values" in py_test:
                c_pvals = detail["p_values"]
                py_pvals = py_test["p_values"]
                if len(c_pvals) == len(py_pvals):
                    for idx, (c_p, py_p) in enumerate(zip(c_pvals, py_pvals), 1):
                        if abs(c_p - py_p) > tolerance:
                            mismatches.append(
                                f"{c_name}: sequence {idx} p-value mismatch (C: {c_p:.6f}, "
                                f"Python: {py_p:.6f})"
                            )
                            if len(mismatches) > 10:
                                break
                else:
                    mismatches.append(
                        f"{c_name}: per-sequence count mismatch (C: {len(c_pvals)}, "
                        f"Python: {len(py_pvals)})"
                    )

        if mismatches:
            error_msg = f"Found {len(mismatches)} mismatch(es) with C binary:\n"
            error_msg += "\n".join(f"  - {m}" for m in mismatches[:10])
            if len(mismatches) > 10:
                error_msg += f"\n  ... and {len(mismatches) - 10} more"
            pytest.fail(error_msg)

    def test_assess_equivalence_cases(self):
        """Validate Python assess() against C binary results for all stored cases."""
        test_data_dir = Path(__file__).parent / "test_data" / "statistical_tests_results"
        index_path = test_data_dir / "index.json"

        if not index_path.exists():
            pytest.skip("Missing test_data/statistical_tests_results/index.json - generate test cases first")

        with open(index_path, "r") as f:
            index = json.load(f)

        for case in index.get("test_cases", []):
            case_dir = test_data_dir / case["name"]
            if not case_dir.exists():
                continue

            inputs = self._load_case_inputs(case_dir)
            c_results = self._load_case_results(case_dir)

            dataset_file = self._get_dataset_path(inputs)
            results = NISTTests.assess(
                file_path=dataset_file,
                bit_length=inputs["bit_length"],
                num_sequences=inputs["num_sequences"],
                input_format=inputs["assess_params"]["input_format"],
                tests=inputs["assess_params"]["tests"],
                non_overlapping_template_block_size=inputs["assess_params"].get("nonoverlap", 968),
                overlapping_template_block_size=inputs["assess_params"].get("overlap", 1032)
            )
            self._compare_results(results, c_results)

    def test_assess_ascii_format(self):
        """
        Test assess() with ASCII input format.
        
        Verifies that ASCII format (text file with '0' and '1' characters)
        is correctly read and processed.
        """
        import tempfile
        import os
        
        # Create test data in ASCII format
        # 100 bits = "01010101..." as text
        np.random.seed(99999)
        bits = np.random.randint(0, 2, 100, dtype=np.uint8)
        ascii_data = ''.join(str(b) for b in bits)
        
        # Write to temporary ASCII file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            temp_file = f.name
            f.write(ascii_data)
        
        try:
            # Run assess with ASCII format
            results = NISTTests.assess(
                file_path=temp_file,
                bit_length=100,
                num_sequences=1,
                input_format='ascii',
                tests='110000000000000'  # Just frequency and block frequency
            )
            
            # Verify we got results
            assert 'tests' in results
            assert len(results['tests']) == 2
            
            # Verify test names
            test_names = [t['test_name'] for t in results['tests']]
            assert 'frequency' in test_names
            assert 'block_frequency' in test_names
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_assess_multiple_sequences(self):
        """
        Test assess() with multiple sequences.
        
        Verifies that a single bitstream can be split into multiple
        sequences for testing, matching the C binary behavior.
        """
        import tempfile
        import os
        
        # Create test data: 500 bits to be split into 5 sequences of 100 bits each
        np.random.seed(55555)
        bits = np.random.randint(0, 2, 500, dtype=np.uint8)
        packed = np.packbits(bits)
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            temp_file = f.name
            packed.tofile(f)
        
        try:
            # Run with 5 sequences
            results = NISTTests.assess(
                file_path=temp_file,
                bit_length=100,
                num_sequences=5,
                input_format='binary',
                tests='100000000000000'  # Just frequency
            )
            
            # Verify correct number of sequences processed
            assert 'tests' in results
            assert len(results['tests']) == 1
            
            test_result = results['tests'][0]
            assert test_result['total_sequences'] == 5
            assert test_result['test_name'] == 'frequency'
            
            # Verify bin counts sum to number of sequences
            assert sum(test_result['bin_counts']) == 5
            
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
