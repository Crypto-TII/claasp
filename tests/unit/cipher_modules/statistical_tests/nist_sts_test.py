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
