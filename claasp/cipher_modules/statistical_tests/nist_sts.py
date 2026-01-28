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


"""
Pure Python implementation of NIST Statistical Test Suite (STS)

This module implements the 15 statistical tests from the NIST Special Publication 800-22
for testing randomness of binary sequences.

Reference:
    A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications
    NIST Special Publication 800-22 Revision 1a (April 2010)
    https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final

EXAMPLES:

Testing a dataset in byte-oriented format (packed binary)::

    sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
    sage: import numpy as np
    sage: 
    sage: # Example 1: Test random bytes from a cryptographic PRNG
    sage: # Generate 10,000 bytes (80,000 bits) of random data
    sage: # Note: Use a cryptographic PRNG or cipher output for real testing
    sage: np.random.seed(42)
    sage: random_bytes = np.random.randint(0, 256, size=10000, dtype=np.uint8)
    sage: 
    sage: # Run the frequency test (monobit test)
    sage: result = NISTTests.frequency_test(random_bytes)
    sage: result['passed']
    True
    sage: # p_value should be between 0.01 and 1.0 for random data
    sage: 0.01 <= result['p_value'] <= 1.0
    True
    sage: 
    sage: # Run block frequency test with 128-bit blocks
    sage: result = NISTTests.block_frequency_test(random_bytes, block_size=128)
    sage: result['passed']
    True
    sage: 
    sage: # Example 2: Test cipher output (e.g., AES-CTR)
    sage: # Simulate cipher output as packed bytes
    sage: cipher_output = bytes([0x3a, 0xd7, 0x7b, 0xb4, 0x0d] * 2000)  # 10,000 bytes
    sage: result = NISTTests.runs_test(cipher_output)
    sage: result['passed'] # test should fail as the dataset is built from repeating pattern
    False
    sage: 
    sage: # Example 3: Test data from file (byte format)
    sage: # with open('random_data.bin', 'rb') as f:
    sage: #     binary_data = f.read()
    sage: # result = NISTTests.frequency_test(binary_data)

Testing a dataset in ASCII format (one bit per byte, '0' and '1' characters)::

    sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
    sage: import numpy as np
    sage: 
    sage: # Example 1: Test ASCII bit string
    sage: # Create a string of ASCII '0' and '1' characters with equal 0s and 1s
    sage: ascii_bits = "10110010" * 10000  # 80,000 bits as ASCII string (exactly 40,000 ones and 40,000 zeros)
    sage: 
    sage: # Convert ASCII string to binary array
    sage: binary_array = np.array([int(b) for b in ascii_bits], dtype=np.uint8)
    sage: 
    sage: # Run tests on the binary array - should pass with p-value = 1.0
    sage: result = NISTTests.frequency_test(binary_array)
    sage: result['passed']
    True
    sage: result['p_value']
    1.0
    sage: 
    sage: # Example 2: Test ASCII bit string from file
    sage: # with open('bits.txt', 'r') as f:
    sage: #     ascii_string = f.read().strip()
    sage: # binary_array = np.array([int(b) for b in ascii_string], dtype=np.uint8)
    sage: # result = NISTTests.frequency_test(binary_array)
    sage: 
    sage: # Example 3: Alternative compact conversion for ASCII format
    sage: # Pattern with equal 0s and 1s - should give perfect p-value
    sage: ascii_bits = "11010010" * 10000
    sage: binary_array = np.array(list(map(int, ascii_bits)), dtype=np.uint8)
    sage: result = NISTTests.block_frequency_test(binary_array, block_size=64)
    sage: result['p_value']
    1.0

Running all NIST tests on a single sequence::

    sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
    sage: import numpy as np
    sage: 
    sage: # Generate random data for testing
    sage: np.random.seed(42)
    sage: random_bytes = np.random.randint(0, 256, size=10000, dtype=np.uint8)
    sage: 
    sage: # Run all tests on a single sequence using run_all_tests
    sage: sequences = [random_bytes]  # Pass as list with one sequence
    sage: results = NISTTests.run_all_tests(sequences)
    sage: 
    sage: # Or run specific tests with custom significance level
    sage: results = NISTTests.run_all_tests(sequences, test_names=['frequency', 'runs', 'dft'], alpha=0.05)
    sage: 
    sage: # Check how many tests were run
    sage: len(results['tests'])
    3
    sage: 
    sage: # Check individual test results
    sage: results['tests'][0]['test_name']
    'frequency'
    sage: results['tests'][0]['passed']
    True

Running the complete NIST test suite on multiple sequences::

    sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTestRunner
    sage: import numpy as np
    sage: 
    sage: # Generate 10 sequences of 100,000 bits each (byte format)
    sage: num_sequences = 10
    sage: bits_per_sequence = 100000
    sage: bytes_per_sequence = bits_per_sequence // 8
    sage: 
    sage: sequences = []
    sage: for i in range(num_sequences):
    sage:     # Each sequence as packed bytes
    sage:     seq = np.random.randint(0, 256, size=bytes_per_sequence, dtype=np.uint8)
    sage:     sequences.append(seq)
    sage: 
    sage: # Run all NIST tests on the sequences
    sage: runner = NISTTestRunner(sequences, bit_length=bits_per_sequence)
    sage: results = runner.run_all_tests()
    sage: 
    sage: # Print summary report
    sage: print(runner.format_results_summary(results))  # doctest: +SKIP
    sage: 
    sage: # Check overall assessment
    sage: print(f"Overall randomness: {results['overall_assessment']}")  # doctest: +SKIP
    Overall randomness: PASS

Summary of input format support:

1. **Byte-oriented (packed binary)**: Most efficient format
   - bytes, bytearray: ``b'\\xA5\\x3F...'``
   - numpy array of uint8 (0-255): ``np.array([165, 63, ...], dtype=np.uint8)``
   - Bits extracted in big-endian order (MSB first)
   - **Important**: For testing, use cryptographic-quality random data or actual
     cipher output. numpy.random.randint() is deterministic and may produce
     sequences with detectable patterns for large sample sizes (>100KB).

2. **ASCII format (one bit per byte)**:
   - String of '0' and '1' characters: ``"10110010..."``
   - Convert to binary array: ``np.array([int(b) for b in string], dtype=np.uint8)``
   - Or list comprehension: ``np.array(list(map(int, string)), dtype=np.uint8)``

3. **Binary array (preprocessed)**:
   - numpy array of 0s and 1s: ``np.array([1,0,1,1,0,0,1,0], dtype=np.uint8)``
   - This format is used internally and passed through unchanged

**Note on sample size**: NIST recommends testing sequences of at least 100,000 bits.
Larger samples (1 million+ bits) provide more statistical power but require
higher-quality random sources to avoid false failures.
"""

import numpy as np
import math
from scipy import special as spc
from scipy.stats import chi2, norm
from scipy.fft import fft


class NISTTests:
    """
    Implementation of NIST Statistical Test Suite in pure Python.

    This class provides all 15 statistical tests specified in NIST SP 800-22rev1a.
    
    All test methods support two input formats:
    1. Binary array: numpy array of 0s and 1s (uint8)
    2. Packed bytes: bytes, bytearray, or list of integers (0-255)
    
    For packed bytes, bits are extracted in big-endian order (MSB first).
    """

    _TEMPLATE_CACHE = {}

    @staticmethod
    def _find_template_file(m):
        from pathlib import Path

        candidates = []
        current = Path(__file__).resolve()
        for parent in current.parents:
            candidates.append(parent / "sts-2.1.2-modified" / "templates" / f"template{m}")
        candidates.append(Path("/opt") / "sts-2.1.2-modified" / "templates" / f"template{m}")
        candidates.append(Path.cwd() / "sts-2.1.2-modified" / "templates" / f"template{m}")

        for path in candidates:
            if path.exists():
                return path
        return None

    @staticmethod
    def _load_nonoverlap_templates(m):
        if m in NISTTests._TEMPLATE_CACHE:
            return NISTTests._TEMPLATE_CACHE[m]

        template_file = NISTTests._find_template_file(m)
        if template_file is None:
            raise FileNotFoundError(f"Template file for m={m} not found")

        templates = []
        with open(template_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                bits = [int(x) for x in line.split()]
                templates.append(np.array(bits, dtype=np.uint8))

        NISTTests._TEMPLATE_CACHE[m] = templates
        return templates

    @staticmethod
    def _ensure_binary_array(data):
        """
        Convert input data to binary array format if needed.
        
        INPUT:
        
        - ``data`` -- **numpy array**, **bytes**, **bytearray**, or **list**; input data
        
        OUTPUT:
        
        - **numpy array**; binary array of 0s and 1s (uint8)
        
        EXAMPLES::
        
            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: # From packed bytes
            sage: binary = NISTTests._ensure_binary_array(b'\\xA5')
            sage: list(binary)
            [1, 0, 1, 0, 0, 1, 0, 1]
            sage: # From binary array (pass-through)
            sage: arr = np.array([1, 0, 1, 0], dtype=np.uint8)
            sage: result = NISTTests._ensure_binary_array(arr)
            sage: np.array_equal(arr, result)
            True
        """
        # If already a numpy array with only 0s and 1s, return as-is (fast path)
        if isinstance(data, np.ndarray):
            if data.dtype == np.uint8 and len(data) > 0 and np.all((data == 0) | (data == 1)):
                return data
        
        # Convert bytes/bytearray to binary array using numpy.unpackbits (very fast)
        if isinstance(data, (bytes, bytearray)):
            return np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        
        # Convert list of integers to binary array
        if isinstance(data, list):
            # Assume it's a list of bytes (0-255)
            if all(isinstance(x, int) and 0 <= x <= 255 for x in data):
                return np.unpackbits(np.array(data, dtype=np.uint8))
            # Otherwise assume it's already binary
            else:
                return np.array(data, dtype=np.uint8)
        
        # If numpy array but not validated, check if it needs conversion
        if isinstance(data, np.ndarray):
            # If values are > 1, assume they're bytes
            if data.max() > 1:
                return np.unpackbits(data.astype(np.uint8))
            else:
                return data.astype(np.uint8)
        
        raise ValueError(f"Unsupported input type: {type(data)}")

    @staticmethod
    def frequency_test(binary_data):
        """
        Frequency (Monobit) Test.

        The focus of the test is the proportion of zeroes and ones for the entire sequence.
        The purpose of this test is to determine whether the number of ones and zeros in a
        sequence are approximately the same as would be expected for a truly random sequence.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s

        OUTPUT:

        - **dict**; contains 'p_value', 'passed', and 'computational_information'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.frequency_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1 (use float to avoid uint8 overflow)
        sn = np.sum(2.0 * binary_data - 1.0)
        s_obs = np.abs(sn) / np.sqrt(n)
        p_value = spc.erfc(s_obs / np.sqrt(2))

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'sn': float(sn),
                'sn_over_n': float(sn) / n
            }
        }

    @staticmethod
    def block_frequency_test(binary_data, block_size=128):
        """
        Frequency Test within a Block.

        The focus of the test is the proportion of ones within M-bit blocks.
        The purpose of this test is to determine whether the frequency of ones in an M-bit
        block is approximately M/2, as would be expected under an assumption of randomness.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s
        - ``block_size`` -- **integer** (default: `128`); length of each block

        OUTPUT:

        - **dict**; contains 'p_value', 'passed', and 'computational_information'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.block_frequency_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        num_blocks = n // block_size

        if num_blocks < 1:
            return {
                'p_value': np.nan,
                'passed': None,
                'computational_information': {
                    'block_size': np.nan,
                    'num_blocks': np.nan,
                    'chi_squared': np.nan,
                    'discarded_bits': np.nan,
                }
            }

        used_bits = num_blocks * block_size
        discarded_bits = n - used_bits
        block_data = binary_data[:used_bits].reshape((num_blocks, block_size))
        proportions = np.mean(block_data, axis=1)
        chi_squared = 4 * block_size * np.sum((proportions - 0.5) ** 2)
        p_value = spc.gammaincc(num_blocks / 2, chi_squared / 2)

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'block_size': int(block_size),
                'num_blocks': int(num_blocks),
                'chi_squared': float(chi_squared),
                'discarded_bits': int(discarded_bits)
            }
        }

    @staticmethod
    def cumulative_sums_test(binary_data, mode=0):
        """
        Cumulative Sums (Cusum) Test.

        The focus of this test is the maximal excursion (from zero) of the random walk defined
        by the cumulative sum of adjusted (-1, +1) digits in the sequence.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s
        - ``mode`` -- **integer** (default: `0`); 0 for forward, 1 for backward

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.cumulative_sums_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1 (use float to avoid uint8 overflow)
        x = 2.0 * binary_data - 1.0

        if mode == 1:  # backward
            x = x[::-1]

        cumsum = np.cumsum(x)
        z = np.max(np.abs(cumsum))

        # Compute p-value
        sum_a = 0.0
        start = int(np.floor((-n / z + 1) / 4))
        end = int(np.floor((n / z - 1) / 4))

        for k in range(start, end + 1):
            sum_a += (norm.cdf((4 * k + 1) * z / np.sqrt(n)) - norm.cdf((4 * k - 1) * z / np.sqrt(n)))

        sum_b = 0.0
        start = int(np.floor((-n / z - 3) / 4))
        end = int(np.floor((n / z - 1) / 4))

        for k in range(start, end + 1):
            sum_b += (norm.cdf((4 * k + 3) * z / np.sqrt(n)) - norm.cdf((4 * k + 1) * z / np.sqrt(n)))

        p_value = 1.0 - sum_a + sum_b

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'mode': int(mode),
                'n': int(n),
                'z': float(z),
                'max_partial_sum': float(z),
                'sum_a': float(sum_a),
                'sum_b': float(sum_b)
            }
        }

    @staticmethod
    def runs_test(binary_data):
        """
        Runs Test.

        The focus of this test is the total number of runs in the sequence, where a run is an
        uninterrupted sequence of identical bits. A run of length k consists of exactly k
        identical bits and is bounded before and after with a bit of the opposite value.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.runs_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        pi = np.mean(binary_data)

        # Pre-test: if pi not approximately 1/2, then the runs test is not applicable
        tau = 2 / np.sqrt(n)
        if np.abs(pi - 0.5) >= tau:
            return {
                'p_value': np.nan,
                'passed': None,
                'computational_information': {
                    'n': np.nan,
                    'pi': np.nan,
                    'tau': np.nan,
                    'runs': np.nan,
                }
            }

        # Count runs
        runs = np.sum(binary_data[1:] != binary_data[:-1]) + 1

        p_value = spc.erfc(np.abs(runs - 2 * n * pi * (1 - pi)) / (2 * np.sqrt(2 * n) * pi * (1 - pi)))

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'n': int(n),
                'pi': float(pi),
                'tau': float(tau),
                'runs': int(runs)
            }
        }

    @staticmethod
    def longest_run_test(binary_data):
        """
        Test for the Longest Run of Ones in a Block.

        The focus of the test is the longest run of ones within M-bit blocks.
        The purpose of this test is to determine whether the length of the longest run of ones
        within the tested sequence is consistent with the length of the longest run of ones
        that would be expected in a random sequence.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.longest_run_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)

        # Determine block size and parameters based on sequence length
        if n < 128:
            return {
                'p_value': np.nan,
                'passed': None,
                'computational_information': {
                    'n': np.nan,
                    'block_size': np.nan,
                    'num_blocks': np.nan,
                    'chi_squared': np.nan,
                    'frequencies': [],
                }
            }
        elif n < 6272:
            m = 8
            v_values = [1, 2, 3, 4]
            pi_values = [0.21484375, 0.3671875, 0.23046875, 0.1875]
        elif n < 750000:
            m = 128
            v_values = [4, 5, 6, 7, 8, 9]
            pi_values = [0.1174035788, 0.242955959, 0.249363483, 0.17517706, 0.102701071, 0.112398847]
        else:
            m = 10000
            v_values = [10, 11, 12, 13, 14, 15, 16]
            pi_values = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]

        num_blocks = n // m
        frequencies = np.zeros(len(pi_values))

        for i in range(num_blocks):
            block = binary_data[i * m:(i + 1) * m]
            zero_idx = np.flatnonzero(block == 0)
            if zero_idx.size == 0:
                longest_run = m
            else:
                indices = np.concatenate(([-1], zero_idx, [m]))
                longest_run = int(np.max(np.diff(indices) - 1))

            # Categorize the longest run
            if longest_run <= v_values[0]:
                frequencies[0] += 1
            elif longest_run >= v_values[-1]:
                frequencies[-1] += 1
            else:
                for j in range(1, len(v_values) - 1):
                    if v_values[j - 1] < longest_run <= v_values[j]:
                        frequencies[j] += 1
                        break

        # Calculate chi-squared statistic
        chi_squared = 0
        for i in range(len(frequencies)):
            pi = pi_values[i] if i < len(pi_values) else 0

            if pi > 0:
                chi_squared += (frequencies[i] - num_blocks * pi) ** 2 / (num_blocks * pi)

        p_value = spc.gammaincc((len(frequencies) - 1) / 2, chi_squared / 2)

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'n': int(n),
                'block_size': int(m),
                'num_blocks': int(num_blocks),
                'chi_squared': float(chi_squared),
                'frequencies': frequencies.tolist()
            }
        }

    @staticmethod
    def rank_test(binary_data):
        """
        Binary Matrix Rank Test.

        The focus of the test is the rank of disjoint sub-matrices of the entire sequence.
        The purpose of this test is to check for linear dependence among fixed length
        substrings of the original sequence.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.rank_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        m = q = 32  # Matrix dimensions
        num_matrices = n // (m * q)

        if num_matrices == 0:
            return {
                'p_value': 0.0,
                'passed': None,
                'computational_information': {
                    'm': int(m),
                    'q': int(q),
                    'num_matrices': 0,
                    'P_32': 0.288788,
                    'P_31': 0.577576,
                    'P_30': 0.133636,
                    'F_32': 0,
                    'F_31': 0,
                    'F_30': 0,
                    'chi_squared': 0.0,
                    'discarded_bits': int(n),
                }
            }

        def gf2_rank(mat):
            mat = mat.copy()
            rows, cols = mat.shape
            rank = 0
            col = 0
            for r in range(rows):
                while col < cols and not mat[r:, col].any():
                    col += 1
                if col >= cols:
                    break

                pivot = r + np.argmax(mat[r:, col])
                if mat[pivot, col] == 0:
                    col += 1
                    if col >= cols:
                        break
                    continue

                if pivot != r:
                    mat[[r, pivot]] = mat[[pivot, r]]

                for rr in range(rows):
                    if rr != r and mat[rr, col]:
                        mat[rr, :] ^= mat[r, :]

                rank += 1
                col += 1
            return rank

        # Count matrices by rank
        fm = 0  # full rank
        fm1 = 0  # rank m-1
        remainder = 0  # remaining

        for i in range(num_matrices):
            # Extract matrix
            block = binary_data[i * m * q:(i + 1) * m * q]
            matrix = block.reshape((m, q)).astype(np.uint8)

            # Compute rank over GF(2)
            rank = gf2_rank(matrix)

            if rank == m:
                fm += 1
            elif rank == m - 1:
                fm1 += 1
            else:
                remainder += 1

        # Calculate chi-squared
        pi_m = 0.288788
        pi_m1 = 0.577576
        pi_remainder = 0.133636

        chi_squared = ((fm - num_matrices * pi_m) ** 2 / (num_matrices * pi_m) +
                       (fm1 - num_matrices * pi_m1) ** 2 / (num_matrices * pi_m1) +
                       (remainder - num_matrices * pi_remainder) ** 2 / (num_matrices * pi_remainder))

        p_value = np.exp(-chi_squared / 2)

        discarded_bits = n - num_matrices * m * q

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'm': int(m),
                'q': int(q),
                'num_matrices': int(num_matrices),
                'P_32': float(pi_m),
                'P_31': float(pi_m1),
                'P_30': float(pi_remainder),
                'F_32': int(fm),
                'F_31': int(fm1),
                'F_30': int(remainder),
                'chi_squared': float(chi_squared)
                ,
                'discarded_bits': int(discarded_bits)
            }
        }

    @staticmethod
    def dft_test(binary_data):
        """
        Discrete Fourier Transform (Spectral) Test.

        The focus of this test is the peak heights in the Discrete Fourier Transform of the sequence.
        The purpose of this test is to detect periodic features (i.e., repetitive patterns that are
        near each other) in the tested sequence that would indicate a deviation from the assumption
        of randomness.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.dft_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1 (use float to avoid uint8 overflow)
        x = 2.0 * binary_data - 1.0

        # Apply DFT
        s = fft(x)
        modulus = np.abs(s[:n // 2])

        # Calculate threshold
        tau = np.sqrt(np.log(1 / 0.05) * n)

        # Theoretical number of peaks
        n0 = 0.95 * n / 2

        # Actual number of peaks below threshold
        n1 = np.sum(modulus < tau)

        # Calculate p-value
        d = (n1 - n0) / np.sqrt(n * 0.95 * 0.05 / 4)
        p_value = spc.erfc(np.abs(d) / np.sqrt(2))

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'n': int(n),
                'tau': float(tau),
                'n0': float(n0),
                'n1': float(n1),
                'd': float(d)
            }
        }

    @staticmethod
    def non_overlapping_template_test(binary_data, template=None, block_size=968):
        """
        Non-overlapping Template Matching Test.

        The focus of this test is the number of occurrences of pre-specified target strings.
        The purpose of this test is to detect generators that produce too many occurrences of
        a given non-periodic (aperiodic) pattern.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s
        - ``template`` -- **numpy array** (default: `None`); template to search for (if None, uses [0,0,0,0,0,0,0,0,1])
        - ``block_size`` -- **integer** (default: `968`); size of each block

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.non_overlapping_template_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)

        # If template is None and block_size is a valid template length, use NIST template set
        if template is None and block_size <= 21:
            m = block_size
            templates = NISTTests._load_nonoverlap_templates(m)

            if n < 8 * m:
                return [
                    {
                        'p_value': np.nan,
                        'passed': None,
                        'template_index': template_idx,
                        'computational_information': {
                            'LAMBDA': np.nan,
                            'M': np.nan,
                            'N': np.nan,
                            'm': np.nan,
                            'n': np.nan,
                            'Index': np.nan,
                            'Template': "not_applicable",
                            'W': [],
                            'Chi^2': np.nan,
                            'P_value': np.nan,
                        }
                    }
                    for template_idx, tmpl in enumerate(templates)
                ]

            results = []
            for template_idx, tmpl in enumerate(templates):
                result = NISTTests.non_overlapping_template_test_given_template(
                    binary_data=binary_data,
                    template=tmpl,
                    num_blocks=8,
                    template_index=template_idx,
                )
                result['template_index'] = template_idx
                results.append(result)

            return results

        if template is None:
            template = np.array([0, 0, 0, 0, 0, 0, 0, 0, 1], dtype=np.uint8)

        # Single template path (legacy behavior)
        if isinstance(template, list):
            template = np.array(template, dtype=np.uint8)

        return NISTTests.non_overlapping_template_test_given_template(
            binary_data=binary_data,
            template=template,
            block_size=block_size,
        )

    @staticmethod
    def non_overlapping_template_test_given_template(binary_data, template, block_size=None, num_blocks=8, template_index=None):
        """
        Non-overlapping Template Matching Test for a single fixed template.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s
        - ``template`` -- **numpy array**; template to search for
        - ``block_size`` -- **integer** (optional); size of each block (M). If None, uses n//num_blocks.
        - ``num_blocks`` -- **integer** (default: `8`); number of blocks (N) when block_size is None.
        - ``template_index`` -- **integer** (optional); index of the template in the NIST template list

        OUTPUT:

        - **dict**; contains 'p_value', 'passed', and 'computational_information'
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)

        if isinstance(template, list):
            template = np.array(template, dtype=np.uint8)

        m = len(template)
        template = template.astype(np.uint8, copy=False)
        template_code = int((template * (1 << np.arange(m - 1, -1, -1, dtype=np.uint64))).sum(dtype=np.uint64))
        powers = (1 << np.arange(m - 1, -1, -1, dtype=np.uint64))
        if block_size is None:
            block_len = n // num_blocks if num_blocks > 0 else 0
        else:
            block_len = int(block_size)
            num_blocks = n // block_len if block_len > 0 else 0

        if num_blocks == 0 or block_len == 0 or block_len < m:
            return {
                'p_value': np.nan,
                'passed': None,
                'computational_information': {
                    'LAMBDA': np.nan,
                    'M': np.nan,
                    'N': np.nan,
                    'm': np.nan,
                    'n': np.nan,
                    'Index': np.nan,
                    'Template': "not_applicable",
                    'W': [],
                    'Chi^2': np.nan,
                    'P_value': np.nan,
                }
            }

        lambda_val = (block_len - m + 1) / (2 ** m)
        var_wj = block_len * ((1 / (2 ** m)) - ((2 * m - 1) / (2 ** (2 * m))))

        if lambda_val <= 0 or var_wj <= 0:
            return {
                'p_value': np.nan,
                'passed': None,
                'computational_information': {
                    'LAMBDA': np.nan,
                    'M': np.nan,
                    'N': np.nan,
                    'm': np.nan,
                    'n': np.nan,
                    'Index': np.nan,
                    'Template': "not_applicable",
                    'W': [],
                    'Chi^2': np.nan,
                    'P_value': np.nan,
                }
            }

        wj = []
        for i in range(num_blocks):
            block = binary_data[i * block_len:(i + 1) * block_len]
            num_windows = block_len - m + 1
            if num_windows <= 0:
                wj.append(0)
                continue

            stride = block.strides[0]
            windows = np.lib.stride_tricks.as_strided(
                block,
                shape=(num_windows, m),
                strides=(stride, stride),
                writeable=False,
            )
            codes = (windows * powers).sum(axis=1, dtype=np.uint64)
            matches = np.flatnonzero(codes == template_code)

            count = 0
            current_pos = 0
            while True:
                idx = np.searchsorted(matches, current_pos)
                if idx >= len(matches):
                    break
                count += 1
                current_pos = matches[idx] + m
            wj.append(count)

        chi_squared = np.sum(((np.array(wj) - lambda_val) / np.sqrt(var_wj)) ** 2)
        p_value = spc.gammaincc(num_blocks / 2, chi_squared / 2)

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'LAMBDA': float(lambda_val),
                'M': int(block_len),
                'N': int(num_blocks),
                'm': int(m),
                'n': int(n),
                'Index': int(template_index) if template_index is not None else -1,
                'Template': ''.join(str(x) for x in template.tolist()),
                'W': wj,
                'Chi^2': float(chi_squared),
                'P_value': float(p_value)
            }
        }

    @staticmethod
    def overlapping_template_test(binary_data, template=None, block_size=1032):
        """
        Overlapping Template Matching Test.

        The focus of the test is the number of occurrences of pre-specified target strings.
        The purpose of this test is to detect generators that produce too many occurrences of
        a given non-periodic (aperiodic) pattern. This test uses overlapping matching.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s
        - ``template`` -- **numpy array** (default: `None`); template to search for (if None, uses [1,1,1,1,1,1,1,1,1])
        - ``block_size`` -- **integer** (default: `1032`); size of each block

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.overlapping_template_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        if template is None and block_size <= 21:
            template = np.ones(block_size, dtype=np.uint8)
            block_size = 1032
        elif template is None:
            template = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1], dtype=np.uint8)

        n = len(binary_data)
        m = len(template)
        template = template.astype(np.uint8, copy=False)
        template_code = int((template * (1 << np.arange(m - 1, -1, -1, dtype=np.uint64))).sum(dtype=np.uint64))
        powers = (1 << np.arange(m - 1, -1, -1, dtype=np.uint64))
        num_blocks = n // block_size

        # Theoretical values for m=9
        lambda_val = (block_size - m + 1) / (2 ** m)
        eta = lambda_val / 2

        if num_blocks == 0:
            return {
                'p_value': np.nan,
                'passed': None,
                'computational_information': {
                    'n': int(n),
                    'm': int(m),
                    'M': int(block_size),
                    'N': int(num_blocks),
                    'LAMBDA': float(lambda_val),
                    'eta': float(eta),
                    'FREQUENCY_0_1_2_3_4_>=5': [0, 0, 0, 0, 0, 0],
                    'Chi^2': np.nan,
                    'P_value': np.nan,
                }
            }

        import math

        def _overlap_pr(u, eta_val):
            if u == 0:
                return math.exp(-eta_val)
            sum_val = 0.0
            for l in range(1, u + 1):
                sum_val += math.exp(
                    -eta_val
                    - u * math.log(2)
                    + l * math.log(eta_val)
                    - math.lgamma(l + 1)
                    + math.lgamma(u)
                    - math.lgamma(l)
                    - math.lgamma(u - l + 1)
                )
            return sum_val

        # Probabilities for different occurrence counts (for m=9)
        pi = [_overlap_pr(i, eta) for i in range(5)]
        pi.append(1.0 - sum(pi))

        v_counts = [0] * 6

        for i in range(num_blocks):
            block = binary_data[i * block_size:(i + 1) * block_size]
            num_windows = block_size - m + 1
            if num_windows <= 0:
                count = 0
            else:
                stride = block.strides[0]
                windows = np.lib.stride_tricks.as_strided(
                    block,
                    shape=(num_windows, m),
                    strides=(stride, stride),
                    writeable=False,
                )
                codes = (windows * powers).sum(axis=1, dtype=np.uint64)
                count = int(np.count_nonzero(codes == template_code))

            if count <= 4:
                v_counts[count] += 1
            else:
                v_counts[5] += 1

        # Calculate chi-squared
        chi_squared = 0
        for i in range(6):
            chi_squared += (v_counts[i] - num_blocks * pi[i]) ** 2 / (num_blocks * pi[i])

        p_value = spc.gammaincc(5 / 2, chi_squared / 2)

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'n': int(n),
                'm': int(m),
                'M': int(block_size),
                'N': int(num_blocks),
                'LAMBDA': float(lambda_val),
                'eta': float(eta),
                'FREQUENCY_0_1_2_3_4_>=5': v_counts,
                'Chi^2': float(chi_squared),
                'P_value': float(p_value),
            }
        }

    @staticmethod
    def universal_test(binary_data):
        """
        Maurer's Universal Statistical Test.

        The focus of this test is the number of bits between matching patterns.
        The purpose of the test is to detect whether or not the sequence can be significantly
        compressed without loss of information.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 100000, dtype=np.uint8)
            sage: result = NISTTests.universal_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)

        # Set L and Q based on n
        if n < 387840:
            not_applicable = float("nan")
            return {
                'p_value': not_applicable,
                'passed': None,
                'computational_information': {
                    'n': not_applicable,
                    'L': not_applicable,
                    'Q': not_applicable,
                    'K': not_applicable,
                    'fn': not_applicable,
                    'expected_value': not_applicable,
                    'sigma': not_applicable,
                }
            }
        elif n < 904960:
            L, Q = 6, 640
        elif n < 2068480:
            L, Q = 7, 1280
        elif n < 4654080:
            L, Q = 8, 2560
        elif n < 10342400:
            L, Q = 9, 5120
        elif n < 22753280:
            L, Q = 10, 10240
        elif n < 49643520:
            L, Q = 11, 20480
        elif n < 107560960:
            L, Q = 12, 40960
        elif n < 231669760:
            L, Q = 13, 81920
        elif n < 496435200:
            L, Q = 14, 163840
        else:
            L, Q = 15, 327680

        K = n // L - Q

        total_blocks = Q + K
        bits = binary_data[:total_blocks * L]
        powers = (1 << np.arange(L - 1, -1, -1, dtype=np.uint64))
        blocks = bits.reshape((-1, L))
        patterns = (blocks * powers).sum(axis=1, dtype=np.uint64).astype(np.int64, copy=False)

        T = np.zeros(1 << L, dtype=np.int64)

        for i in range(Q):
            T[patterns[i]] = i + 1

        sum_log = 0.0
        for i in range(Q, Q + K):
            pattern = patterns[i]
            last = T[pattern]
            distance = (i + 1 - last) if last else (i + 1)
            sum_log += np.log2(distance)
            T[pattern] = i + 1

        fn = sum_log / K

        # Expected value and variance (from NIST tables)
        expected_value = {
            6: (5.2177052, 2.954),
            7: (6.1962507, 3.125),
            8: (7.1836656, 3.238),
            9: (8.1764248, 3.311),
            10: (9.1723243, 3.356),
            11: (10.170032, 3.384),
            12: (11.168765, 3.401),
            13: (12.168070, 3.410),
            14: (13.167693, 3.416),
            15: (14.167488, 3.419)
        }

        exp_val, variance = expected_value[L]

        c = 0.7 - 0.8 / L + (4 + 32 / L) * (K ** (-3 / L)) / 15
        sigma = c * np.sqrt(variance / K)

        p_value = spc.erfc(np.abs(fn - exp_val) / (np.sqrt(2) * sigma))

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'n': int(n),
                'L': int(L),
                'Q': int(Q),
                'K': int(K),
                'fn': float(fn),
                'expected_value': float(exp_val),
                'sigma': float(sigma)
            }
        }

    @staticmethod
    def approximate_entropy_test(binary_data, m=10):
        """
        Approximate Entropy Test.

        The focus of this test is the frequency of all possible overlapping m-bit patterns
        across the entire sequence. The purpose of the test is to compare the frequency of
        overlapping blocks of two consecutive/adjacent lengths (m and m+1) against the expected
        result for a random sequence.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s
        - ``m`` -- **integer** (default: `10`); length of each block

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.approximate_entropy_test(binary_data, m=2)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)

        # Augment the sequence
        augmented = np.concatenate([binary_data, binary_data[:m]])

        def calculate_phi(m_val):
            if m_val <= 0:
                return np.nan

            powers = (1 << np.arange(m_val - 1, -1, -1, dtype=np.uint64))
            stride = augmented.strides[0]
            windows = np.lib.stride_tricks.as_strided(
                augmented,
                shape=(n, m_val),
                strides=(stride, stride),
                writeable=False
            )
            patterns = (windows * powers).sum(axis=1, dtype=np.uint64).astype(np.int64, copy=False)
            counts = np.bincount(patterns, minlength=1 << m_val)
            nonzero = counts[counts > 0]
            phi = np.sum(nonzero * np.log(nonzero / n))
            return phi / n

        phi_m = calculate_phi(m)
        phi_m_plus_1 = calculate_phi(m + 1)

        apen = phi_m - phi_m_plus_1
        chi_squared = 2 * n * (np.log(2) - apen)

        p_value = spc.gammaincc(2 ** (m - 1), chi_squared / 2)

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'm': int(m),
                'apen': float(apen),
                'chi_squared': float(chi_squared)
            }
        }

    @staticmethod
    def random_excursions_test(binary_data):
        """
        Random Excursions Test.

        The focus of this test is the number of cycles having exactly K visits in a cumulative
        sum random walk. The cumulative sum random walk is derived from partial sums after the
        (0,1) sequence is transferred to the appropriate (-1, +1) sequence.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s

        OUTPUT:

        - **dict**; contains 'p_values' (list for each state) and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.random_excursions_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1 (use float to avoid uint8 overflow)
        x = 2.0 * binary_data - 1.0

        # Calculate cumulative sum
        cumsum = np.concatenate(([0], np.cumsum(x), [0]))

        # Find cycles (returns to zero)
        zero_crossings = np.where(cumsum == 0)[0]
        num_cycles = len(zero_crossings) - 1

        if num_cycles < 500:
            return {
                'p_values': [np.nan] * 8,
                'passed': None,
                'num_cycles': num_cycles,
                'testable': False,
                'computational_information': {
                    'num_cycles': np.nan,
                    'testable': np.nan,
                }
            }

        states = [-4, -3, -2, -1, 1, 2, 3, 4]
        p_values = []

        for x_val in states:
            positions = np.where(cumsum == x_val)[0]
            if positions.size == 0:
                visits = np.zeros(num_cycles, dtype=np.int64)
            else:
                idx = np.searchsorted(positions, zero_crossings)
                visits = np.diff(idx)

            visits = np.clip(visits, 0, 5)
            v = np.bincount(visits, minlength=6).astype(float)

            # Theoretical probabilities (match sts-2.1.2-modified table)
            pi_values = {
                1: [0.5, 0.25, 0.125, 0.0625, 0.03125, 0.03125],
                2: [0.75, 0.0625, 0.046875, 0.03515625, 0.0263671875, 0.0791015625],
                3: [0.8333333333, 0.02777777778, 0.02314814815, 0.01929012346, 0.01607510288, 0.0803755143],
                4: [0.875, 0.015625, 0.013671875, 0.01196289063, 0.01046752930, 0.0732727051]
            }

            pi = np.array(pi_values[abs(x_val)])

            # Calculate chi-squared
            chi_squared = 0.0
            for k in range(6):
                if pi[k] > 0:
                    chi_squared += (v[k] - num_cycles * pi[k]) ** 2 / (num_cycles * pi[k])

            p_value = spc.gammaincc(5 / 2, chi_squared / 2)
            p_values.append(p_value)

        # Test passes if all p-values >= 0.01
        passed = all(p >= 0.01 for p in p_values)

        return {
            'p_values': p_values,
            'passed': passed,
            'num_cycles': num_cycles,
            'testable': True,
            'computational_information': {
                'num_cycles': int(num_cycles),
                'testable': True
            }
        }

    @staticmethod
    def random_excursions_variant_test(binary_data):
        """
        Random Excursions Variant Test.

        The focus of this test is the total number of times that a particular state is visited
        (i.e., occurs) in a cumulative sum random walk.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s

        OUTPUT:

        - **dict**; contains 'p_values' (list for each state) and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.random_excursions_variant_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1 (avoid uint8 overflow)
        x = binary_data.astype(np.int64) * 2 - 1

        # Calculate cumulative sum (NIST STS style)
        s_k = np.cumsum(x, dtype=np.int64)
        num_cycles = int(np.count_nonzero(s_k == 0))
        if s_k[-1] != 0:
            num_cycles += 1

        constraint = max(0.005 * math.sqrt(n), 500)
        if num_cycles < constraint:
            return {
                'p_values': [np.nan] * 18,
                'passed': None,
                'num_cycles': num_cycles,
                'testable': False,
                'computational_information': {
                    'num_cycles': np.nan,
                    'testable': np.nan,
                }
            }

        states = list(range(-9, 0)) + list(range(1, 10))
        p_values = []

        for x_val in states:
            # Count total occurrences of state x_val
            count = int(np.sum(s_k == x_val))

            # Calculate p-value
            p_value = spc.erfc(np.abs(count - num_cycles) / np.sqrt(2 * num_cycles * (4 * abs(x_val) - 2)))
            p_values.append(p_value)

        # Test passes if all p-values >= 0.01
        passed = all(p >= 0.01 for p in p_values)

        return {
            'p_values': p_values,
            'passed': passed,
            'num_cycles': num_cycles,
            'testable': True,
            'computational_information': {
                'num_cycles': int(num_cycles),
                'testable': True
            }
        }

    @staticmethod
    def serial_test(binary_data, m=16):
        """
        Serial Test.

        The focus of this test is the frequency of all possible overlapping m-bit patterns
        across the entire sequence. The purpose of this test is to determine whether the number
        of occurrences of the 2^m m-bit overlapping patterns is approximately the same as would
        be expected for a random sequence.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s
        - ``m`` -- **integer** (default: `16`); length of each block

        OUTPUT:

        - **dict**; contains 'p_value1', 'p_value2', and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.serial_test(binary_data, m=2)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)

        if m < 2:
            return {
                'p_value1': np.nan,
                'p_value2': np.nan,
                'passed': False,
                'computational_information': {
                    'n': int(n),
                    'm': int(m),
                    'psi_m': np.nan,
                    'psi_m_minus_1': np.nan,
                    'psi_m_minus_2': np.nan,
                    'delta1': np.nan,
                    'delta2': np.nan
                }
            }

        # Augment the sequence
        augmented = np.concatenate([binary_data, binary_data[:m - 1]])

        def calculate_psi_squared(m_val):
            if m_val <= 0:
                return np.nan

            powers = (1 << np.arange(m_val - 1, -1, -1, dtype=np.uint64))
            stride = augmented.strides[0]
            windows = np.lib.stride_tricks.as_strided(
                augmented,
                shape=(n, m_val),
                strides=(stride, stride),
                writeable=False
            )
            patterns = (windows * powers).sum(axis=1, dtype=np.uint64).astype(np.int64, copy=False)
            counts = np.bincount(patterns, minlength=1 << m_val)
            psi_squared = (np.square(counts).sum() * (2 ** m_val) / n) - n
            return psi_squared

        psi_m = calculate_psi_squared(m)
        psi_m_minus_1 = calculate_psi_squared(m - 1)
        psi_m_minus_2 = calculate_psi_squared(m - 2)

        delta1 = psi_m - psi_m_minus_1
        delta2 = psi_m - 2 * psi_m_minus_1 + psi_m_minus_2

        p_value1 = spc.gammaincc(2 ** (m - 1) / 2, delta1 / 2)
        p_value2 = spc.gammaincc(2 ** (m - 2) / 2, delta2 / 2)

        passed = p_value1 >= 0.01 and p_value2 >= 0.01

        return {
            'p_value1': p_value1,
            'p_value2': p_value2,
            'passed': passed,
            'computational_information': {
                'n': int(n),
                'm': int(m),
                'psi_m': float(psi_m),
                'psi_m_minus_1': float(psi_m_minus_1),
                'psi_m_minus_2': float(psi_m_minus_2),
                'delta1': float(delta1),
                'delta2': float(delta2)
            }
        }

    @staticmethod
    def linear_complexity_test(binary_data, block_size=500):
        """
        Linear Complexity Test.

        The focus of this test is the length of a linear feedback shift register (LFSR).
        The purpose of this test is to determine whether or not the sequence is complex enough
        to be considered random.

        INPUT:

        - ``binary_data`` -- **numpy array**; binary sequence as numpy array of 0s and 1s
        - ``block_size`` -- **integer** (default: `500`); size of each block (M)

        OUTPUT:

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.linear_complexity_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        num_blocks = n // block_size

        if num_blocks < 1:
            discarded_bits = int(n)
            return {
                'p_value': np.nan,
                'passed': None,
                'computational_information': {
                    'block_size': np.nan,
                    'num_blocks': np.nan,
                    'mu': np.nan,
                    'chi_squared': np.nan,
                    't_values': [],
                    'M': int(block_size),
                    'N': int(num_blocks),
                    'frequency': [0, 0, 0, 0, 0, 0, 0],
                    'discarded_bits': discarded_bits,
                    'chi_square': np.nan,
                    'p_value': np.nan,
                }
            }

        def berlekamp_massey(sequence):
            """Compute linear complexity using a bitset-optimized Berlekamp-Massey algorithm."""
            n_seq = len(sequence)
            if n_seq == 0:
                return 0

            popcount = int.bit_count if hasattr(int, "bit_count") else lambda x: bin(x).count("1")

            c = 1  # connection polynomial
            b = 1  # copy of previous c
            l = 0
            m = -1

            window = 0  # bit 0 holds s[N-1], bit 1 holds s[N-2], ...
            max_mask = (1 << n_seq) - 1

            for i in range(n_seq):
                if l:
                    d = sequence[i] ^ (popcount((c >> 1) & window) & 1)
                else:
                    d = sequence[i]

                if d:
                    t = c
                    c ^= b << (i - m)
                    if l <= i // 2:
                        l = i + 1 - l
                        m = i
                        b = t

                window = ((window << 1) | sequence[i]) & max_mask

            return l

        # Expected mean
        mu = block_size / 2 + (9 + (-1) ** (block_size + 1)) / 36 - (block_size / 3 + 2 / 9) / (2 ** block_size)

        # Calculate linear complexity for each block
        t_values = np.zeros(7)  # Categories: v < -2.5, -2.5 to -1.5, ..., > 2.5

        for i in range(num_blocks):
            block = binary_data[i * block_size:(i + 1) * block_size]
            lc = berlekamp_massey(block.tolist())

            # Calculate T statistic
            t = (-1) ** block_size * (lc - mu) + 2 / 9

            # Categorize
            if t <= -2.5:
                t_values[0] += 1
            elif t <= -1.5:
                t_values[1] += 1
            elif t <= -0.5:
                t_values[2] += 1
            elif t <= 0.5:
                t_values[3] += 1
            elif t <= 1.5:
                t_values[4] += 1
            elif t <= 2.5:
                t_values[5] += 1
            else:
                t_values[6] += 1

        # Theoretical probabilities
        pi_values = [0.01047, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833]

        # Calculate chi-squared
        chi_squared = 0.0
        for i in range(7):
            chi_squared += (t_values[i] - num_blocks * pi_values[i]) ** 2 / (num_blocks * pi_values[i])

        p_value = spc.gammaincc(6 / 2, chi_squared / 2)
        discarded_bits = int(n - num_blocks * block_size)

        return {
            'p_value': p_value,
            'passed': p_value >= 0.01,
            'computational_information': {
                'block_size': int(block_size),
                'num_blocks': int(num_blocks),
                'mu': float(mu),
                'chi_squared': float(chi_squared),
                't_values': t_values.tolist(),
                'M': int(block_size),
                'N': int(num_blocks),
                'frequency': t_values.tolist(),
                'discarded_bits': discarded_bits,
                'chi_square': float(chi_squared),
                'p_value': float(p_value),
            }
        }

    @staticmethod
    def uniformity_test(p_values):
        """
        Perform uniformity test on a list of p-values using chi-square test.
        
        This test checks if the p-values are uniformly distributed across 10 bins
        [0, 0.1), [0.1, 0.2), ..., [0.9, 1.0]. This is used to validate that the
        statistical test is working correctly - p-values from a truly random source
        should be uniformly distributed.
        
        INPUT:
        
        - ``p_values`` -- **list** or **numpy array**; list of p-values from test sequences
        
        OUTPUT:
        
        - **dict**; containing:
          - 'bin_counts': Array of 10 integers showing how many p-values fell in each bin
          - 'chi_squared': Chi-squared statistic
          - 'uniformity_p_value': P-value of the uniformity test
          - 'passed': Boolean indicating if uniformity test passed (p-value >= 0.0001)
        
        EXAMPLES::
        
            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: # Uniformly distributed p-values should pass
            sage: uniform_pvalues = np.linspace(0.05, 0.95, 100)
            sage: result = NISTTests.uniformity_test(uniform_pvalues)
            sage: result['passed']
            True
        """
        p_values = np.array(p_values)
        num_sequences = len(p_values)
        
        if num_sequences == 0:
            return {
                'bin_counts': np.zeros(10, dtype=int),
                'chi_squared': 0.0,
                'uniformity_p_value': 0.0,
                'passed': False
            }
        
        # Count p-values in each bin [0, 0.1), [0.1, 0.2), ..., [0.9, 1.0]
        bin_counts = np.zeros(10, dtype=int)
        for p_val in p_values:
            bin_idx = int(np.floor(p_val * 10))
            if bin_idx == 10:  # Handle edge case where p_val == 1.0
                bin_idx = 9
            bin_counts[bin_idx] += 1
        
        # Expected count in each bin (uniform distribution)
        expected_count = num_sequences / 10.0
        
        if expected_count == 0:
            uniformity_p_value = 0.0
        else:
            # Chi-squared statistic
            chi_squared = np.sum((bin_counts - expected_count) ** 2 / expected_count)
            
            # P-value using chi-squared distribution with 9 degrees of freedom
            # Using incomplete gamma function: igamc(df/2, chi2/2)
            uniformity_p_value = spc.gammaincc(9.0 / 2.0, chi_squared / 2.0)
        
        return {
            'bin_counts': bin_counts,
            'chi_squared': chi_squared if expected_count > 0 else 0.0,
            'uniformity_p_value': uniformity_p_value,
            'passed': uniformity_p_value >= 0.0001
        }

    @staticmethod
    def run_all_tests(sequences, test_names=None, alpha=0.01, 
                     block_frequency_block_size=128,
                     non_overlapping_template_block_size=968,
                     overlapping_template_block_size=1032,
                     approximate_entropy_block_size=10,
                     serial_block_size=16,
                     linear_complexity_block_size=500):
        """
        Run NIST statistical tests on multiple sequences and return comprehensive results.
        
        This method mimics the NIST-STS tool behavior by:
        1. Running each test on all sequences
        2. Collecting p-values from each sequence
        3. Computing uniformity test (p-value distribution in 10 bins)
        4. Computing proportion of sequences that passed
        
        INPUT:
        
        - ``sequences`` -- **list of numpy arrays**; list of binary sequences to test
        - ``test_names`` -- **list** (optional); names of tests to run. If None, runs all tests.
          Valid names: 'frequency', 'block_frequency', 'cumulative_sums', 'runs', 'longest_run',
          'rank', 'dft', 'non_overlapping_template', 'overlapping_template', 'universal',
          'approximate_entropy', 'random_excursions', 'random_excursions_variant', 
          'serial', 'linear_complexity'
        - ``alpha`` -- **float** (default: 0.01); significance level for individual test pass/fail
        - ``block_frequency_block_size`` -- **integer** (default: 128); block size for Block Frequency Test
        - ``non_overlapping_template_block_size`` -- **integer** (default: 968); block size for Non-overlapping Template Test
        - ``overlapping_template_block_size`` -- **integer** (default: 1032); block size for Overlapping Template Test
        - ``approximate_entropy_block_size`` -- **integer** (default: 10); m parameter for Approximate Entropy Test
        - ``serial_block_size`` -- **integer** (default: 16); m parameter for Serial Test
        - ``linear_complexity_block_size`` -- **integer** (default: 500); block size for Linear Complexity Test
        
        OUTPUT:
        
        - **dict**; dictionary with test results in NIST-STS format:
          - For each test, includes:
            - 'test_name': Name of the test
            - 'p_values': List of p-values from all sequences
            - 'bin_counts': C1-C10 counts for uniformity test
            - 'uniformity_p_value': P-value of uniformity test
            - 'passed_sequences': Number of sequences that passed
            - 'total_sequences': Total number of sequences tested
            - 'proportion': Proportion of sequences that passed
            - 'passed': Boolean indicating overall test success
        
        EXAMPLES::
        
            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: # Generate 10 random sequences of 10000 bits each
            sage: sequences = [np.random.randint(0, 2, 10000, dtype=np.uint8) for _ in range(10)]
            sage: results = NISTTests.run_all_tests(sequences, test_names=['frequency', 'runs'])
            sage: len(results['tests'])
            3
            sage: 
            sage: # Run with custom block sizes (like assess --blockfreq 64 --serial 32)
            sage: results = NISTTests.run_all_tests(sequences, 
            ....:     test_names=['block_frequency', 'serial'],
            ....:     block_frequency_block_size=64,
            ....:     serial_block_size=32)
            sage: len(results['tests'])
            2
        """
        if test_names is None:
            # Run all tests
            test_names = [
                'frequency', 'block_frequency', 'cumulative_sums', 'runs', 'longest_run',
                'rank', 'dft', 'non_overlapping_template', 'overlapping_template', 'universal',
                'approximate_entropy', 'random_excursions', 'random_excursions_variant',
                'serial', 'linear_complexity'
            ]
        
        # Map test names to methods with custom block sizes
        test_methods = {
            'frequency': NISTTests.frequency_test,
            'block_frequency': lambda seq: NISTTests.block_frequency_test(seq, block_size=block_frequency_block_size),
            'cumulative_sums': lambda seq: [
                NISTTests.cumulative_sums_test(seq, mode=0),
                NISTTests.cumulative_sums_test(seq, mode=1)
            ],
            'runs': NISTTests.runs_test,
            'longest_run': NISTTests.longest_run_test,
            'rank': NISTTests.rank_test,
            'dft': NISTTests.dft_test,
            'non_overlapping_template': lambda seq: NISTTests.non_overlapping_template_test(seq, block_size=non_overlapping_template_block_size),
            'overlapping_template': lambda seq: NISTTests.overlapping_template_test(seq, block_size=overlapping_template_block_size),
            'universal': NISTTests.universal_test,
            'approximate_entropy': lambda seq: NISTTests.approximate_entropy_test(seq, m=approximate_entropy_block_size),
            'random_excursions': NISTTests.random_excursions_test,
            'random_excursions_variant': NISTTests.random_excursions_variant_test,
            'serial': lambda seq: NISTTests.serial_test(seq, m=serial_block_size),
            'linear_complexity': lambda seq: NISTTests.linear_complexity_test(seq, block_size=linear_complexity_block_size)
        }
        
        results = {
            'tests': [],
            'num_sequences': len(sequences),
            'alpha': alpha
        }
        
        for test_name in test_names:
            if test_name not in test_methods:
                continue
            
            test_method = test_methods[test_name]
            all_p_values = []
            test_results = []
            
            # Run test on each sequence
            for seq in sequences:
                try:
                    result = test_method(seq)
                    if (test_name == 'serial' and isinstance(result, dict)
                            and 'p_value1' in result and 'p_value2' in result):
                        test_results.append([
                            {'p_value': result['p_value1'], 'passed': result['p_value1'] >= alpha},
                            {'p_value': result['p_value2'], 'passed': result['p_value2'] >= alpha},
                        ])
                    elif isinstance(result, list):
                        # Multiple results (e.g., cumulative sums, serial)
                        test_results.append(result)
                    else:
                        test_results.append([result])
                except Exception as e:
                    # Test failed
                    test_results.append([{'p_value': 0.0, 'passed': False, 'error': str(e)}])
            
            # Special handling for random excursion tests
            if test_name in ['random_excursions', 'random_excursions_variant']:
                # These tests return multiple p-values per sequence (one per state)
                # and not all sequences may be testable (need num_cycles >= 500)
                
                # Determine number of states
                num_states = 8 if test_name == 'random_excursions' else 18
                state_names = ([-4, -3, -2, -1, 1, 2, 3, 4] if test_name == 'random_excursions' 
                              else list(range(-9, 0)) + list(range(1, 10)))
                
                # Process each state separately
                for state_idx in range(num_states):
                    state_p_values = []
                    testable_count = 0
                    
                    for seq_results in test_results:
                        res = seq_results[0]
                        if res.get('testable', False):
                            # This sequence was testable for random excursion
                            p_vals = res.get('p_values', [])
                            if state_idx < len(p_vals):
                                state_p_values.append(p_vals[state_idx])
                                testable_count += 1
                    
                    # Compute uniformity and proportion for testable sequences only
                    if len(state_p_values) > 0:
                        uniformity_result = NISTTests.uniformity_test(state_p_values)
                        passed_count = sum(1 for p in state_p_values if p >= alpha)
                        
                        # Minimum pass rate calculation (96% of testable sequences)
                        threshold = int(0.96 * testable_count)
                        
                        results['tests'].append({
                            'test_name': f"{test_name}_{state_names[state_idx]}",
                            'p_values': state_p_values,
                            'bin_counts': uniformity_result['bin_counts'].tolist(),
                            'uniformity_p_value': uniformity_result['uniformity_p_value'],
                            'passed_sequences': passed_count,
                            'total_sequences': testable_count,  # Use testable count, not total
                            'proportion': passed_count / testable_count,
                            'passed': uniformity_result['passed'] and passed_count >= threshold
                        })
                continue
            
            # Process results for regular tests
            # Determine if this test returns multiple sub-results
            if len(test_results) > 0 and isinstance(test_results[0], list) and len(test_results[0]) > 1:
                # Multiple sub-tests (e.g., cumulative sums has forward and backward)
                num_subtests = len(test_results[0])
                for subtest_idx in range(num_subtests):
                    subtest_p_values = []
                    for seq_results in test_results:
                        if subtest_idx < len(seq_results):
                            res = seq_results[subtest_idx]
                            p_val = res.get('p_value', res.get('p_value1', 0.0))
                            subtest_p_values.append(p_val)
                    
                    # Compute uniformity and proportion
                    uniformity_result = NISTTests.uniformity_test(subtest_p_values)
                    passed_count = sum(1 for p in subtest_p_values if p >= alpha)
                    
                    # Determine subtest name
                    subtest_name = test_name
                    if test_name == 'cumulative_sums':
                        subtest_name = f"{test_name}_{'forward' if subtest_idx == 0 else 'backward'}"
                    elif test_name == 'serial':
                        subtest_name = f"{test_name}_{subtest_idx + 1}"
                    elif test_name == 'non_overlapping_template':
                        subtest_name = f"{test_name}_{subtest_idx}"
                    
                    results['tests'].append({
                        'test_name': subtest_name,
                        'p_values': subtest_p_values,
                        'bin_counts': uniformity_result['bin_counts'].tolist(),
                        'uniformity_p_value': uniformity_result['uniformity_p_value'],
                        'passed_sequences': passed_count,
                        'total_sequences': len(subtest_p_values),
                        'proportion': passed_count / len(subtest_p_values) if len(subtest_p_values) > 0 else 0.0,
                        'passed': uniformity_result['passed'] and passed_count >= 0.96 * len(subtest_p_values)
                    })
            else:
                # Single result per sequence
                single_p_values = []
                for seq_results in test_results:
                    if isinstance(seq_results, list):
                        res = seq_results[0]
                    else:
                        res = seq_results
                    p_val = res.get('p_value', res.get('p_value1', 0.0))
                    single_p_values.append(p_val)
                
                # Compute uniformity and proportion
                uniformity_result = NISTTests.uniformity_test(single_p_values)
                passed_count = sum(1 for p in single_p_values if p >= alpha)
                
                results['tests'].append({
                    'test_name': test_name,
                    'p_values': single_p_values,
                    'bin_counts': uniformity_result['bin_counts'].tolist(),
                    'uniformity_p_value': uniformity_result['uniformity_p_value'],
                    'passed_sequences': passed_count,
                    'total_sequences': len(single_p_values),
                    'proportion': passed_count / len(single_p_values) if len(single_p_values) > 0 else 0.0,
                    'passed': uniformity_result['passed'] and passed_count >= 0.96 * len(single_p_values)
                })
        
        return results

    @staticmethod
    def format_results_nist_style(results):
        """
        Format test results in NIST-STS output style.
        
        INPUT:
        
        - ``results`` -- **dict**; results from run_all_tests
        
        OUTPUT:
        
        - **str**; formatted string matching NIST-STS output format
        
        EXAMPLES::
        
            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: sequences = [np.random.randint(0, 2, 10000, dtype=np.uint8) for _ in range(10)]
            sage: results = NISTTests.run_all_tests(sequences, test_names=['frequency'])
            sage: output = NISTTests.format_results_nist_style(results)
            sage: 'C1' in output and 'P-VALUE' in output
            True
        """
        lines = []
        lines.append("-" * 110)
        lines.append("RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES")
        lines.append("-" * 110)
        lines.append(" C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST")
        lines.append("-" * 110)
        
        for test in results['tests']:
            # Format bin counts (C1-C10)
            bin_str = "".join(f"{count:3d} " for count in test['bin_counts'])
            
            # Format uniformity p-value
            p_val = test['uniformity_p_value']
            if p_val < 0.0001:
                p_val_str = f"{p_val:8.6f} *"
            else:
                p_val_str = f"{p_val:8.6f}  "
            
            # Format proportion
            prop_str = f"{test['passed_sequences']:4d}/{test['total_sequences']:<4d}"
            
            # Determine if proportion is within acceptable range (96% ± 3σ)
            p_hat = 1.0 - results['alpha']
            n = test['total_sequences']
            if n > 0:
                threshold = 3.0 * np.sqrt((p_hat * results['alpha']) / n)
                prop_min = (p_hat - threshold) * n
                prop_max = (p_hat + threshold) * n
                
                if test['passed_sequences'] < prop_min or test['passed_sequences'] > prop_max:
                    prop_str += " *"
                else:
                    prop_str += "  "
            else:
                prop_str += "  "
            
            # Format test name
            # Handle random excursion test names specially (e.g., "random_excursions_-4" -> "RandomExcursions(-4)")
            test_name_raw = test['test_name']
            if 'random_excursions_' in test_name_raw:
                parts = test_name_raw.rsplit('_', 1)
                if len(parts) == 2:
                    base_name = parts[0].replace('_', '').title()
                    test_name = f"{base_name}({parts[1]})"
                else:
                    test_name = test_name_raw.replace('_', ' ').title()
            else:
                test_name = test_name_raw.replace('_', ' ').title()
            
            line = f"{bin_str} {p_val_str} {prop_str}  {test_name}"
            lines.append(line)
        
        lines.append("-" * 110)
        
        # Add threshold information
        # Calculate thresholds for regular tests and random excursion tests
        n = results['num_sequences']
        p_hat = 1.0 - results['alpha']
        threshold = int((p_hat - 3.0 * np.sqrt((p_hat * results['alpha']) / n)) * n)
        
        # Check if there are random excursion tests and find their sample size
        re_sample_size = None
        re_threshold = None
        for test in results['tests']:
            if 'random_excursion' in test['test_name']:
                if re_sample_size is None or test['total_sequences'] > 0:
                    re_sample_size = test['total_sequences']
                    re_threshold = int((p_hat - 3.0 * np.sqrt((p_hat * results['alpha']) / re_sample_size)) * re_sample_size)
                break
        
        lines.append("The minimum pass rate for each statistical test with the exception of the")
        lines.append("random excursion (variant) test is approximately = {} for a".format(threshold))
        lines.append("sample size = {} binary sequences.".format(n))
        
        if re_sample_size is not None and re_sample_size != n:
            lines.append("")
            lines.append("The minimum pass rate for the random excursion (variant) test")
            lines.append("is approximately = {} for a".format(re_threshold))
            lines.append("sample size = {} binary sequences.".format(re_sample_size))
        
        lines.append("-" * 110)
        
        return "\n".join(lines)

    @staticmethod
    def assess(file_path, bit_length, num_sequences, input_format='binary', 
               tests='111111111111111', alpha=0.01,
               block_frequency_block_size=128,
               non_overlapping_template_block_size=968,
               overlapping_template_block_size=1032,
               approximate_entropy_block_size=10,
               serial_block_size=16,
               linear_complexity_block_size=500):
        """
        Run NIST statistical tests on a dataset file (mimics the original sts-2.1.2 assess binary interface).
        
        This method provides a command-line compatible interface similar to the NIST STS assess binary.
        It reads a file, splits it into sequences, and runs the specified tests.
        
        INPUT:
        
        - ``file_path`` -- **str**; path to input file containing binary data
        - ``bit_length`` -- **int**; number of bits per sequence (like -l/--length flag)
        - ``num_sequences`` -- **int**; number of sequences to test (like -n/--numseq flag)
        - ``input_format`` -- **str** (default: 'binary'); file format:
          * 'binary' or 0: packed binary format (8 bits per byte)
          * 'ascii' or 1: ASCII format (one '0' or '1' character per bit)
        - ``tests`` -- **str** (default: '111111111111111'); 15-character string specifying which tests to run.
          Each position corresponds to a test (1=run, 0=skip):
          Position 1: Frequency, 2: Block Frequency, 3: Cumulative Sums, 4: Runs,
          Position 5: Longest Run, 6: Rank, 7: DFT, 8: Non-overlapping Template,
          Position 9: Overlapping Template, 10: Universal, 11: Approximate Entropy,
          Position 12: Random Excursions, 13: Random Excursions Variant,
          Position 14: Serial, 15: Linear Complexity
        - ``alpha`` -- **float** (default: 0.01); significance level
        - ``block_frequency_block_size`` -- **int** (default: 128); like --blockfreq flag
        - ``non_overlapping_template_block_size`` -- **int** (default: 968); like --nonoverlap flag
        - ``overlapping_template_block_size`` -- **int** (default: 1032); like --overlap flag
        - ``approximate_entropy_block_size`` -- **int** (default: 10); like --entropy flag
        - ``serial_block_size`` -- **int** (default: 16); like --serial flag
        - ``linear_complexity_block_size`` -- **int** (default: 500); like --complexity flag
        
        OUTPUT:
        
        - **dict**; test results from run_all_tests()
        
        EXAMPLES::
        
            sage: from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests
            sage: import numpy as np
            sage: import tempfile
            sage: import os
            sage: 
            sage: # Create a test file with random binary data
            sage: with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
            ....:     test_data = np.random.randint(0, 256, size=12500, dtype=np.uint8)  # 100,000 bits
            ....:     f.write(test_data.tobytes())
            ....:     temp_file = f.name
            sage: 
            sage: # Run assess like: ./assess -l 10000 -n 10 -i 1 -f data.bin -g 0 -t 111111111111111
            sage: # This will print configuration summary and test results to stdout
            sage: results = NISTTests.assess(
            ....:     file_path=temp_file,
            ....:     bit_length=10000,
            ....:     num_sequences=10,
            ....:     input_format='binary',
            ....:     tests='111111111111111'
            ....: )  # doctest: +ELLIPSIS
            <BLANKLINE>
            ========================================================================
            NIST Statistical Test Suite - Python Implementation
            ========================================================================
            Configuration:
              Bitstream length      : 10000
              Number of bitstreams  : 10
              Input format          : Binary
              ...
            sage: results['num_sequences']
            10
            sage: 
            sage: # Run with custom block sizes: ./assess ... --blockfreq 64 --serial 32
            sage: results = NISTTests.assess(
            ....:     file_path=temp_file,
            ....:     bit_length=10000,
            ....:     num_sequences=10,
            ....:     input_format='binary',
            ....:     tests='110000000000000',  # Only Frequency and Block Frequency
            ....:     block_frequency_block_size=64
            ....: )  # doctest: +ELLIPSIS
            <BLANKLINE>
            ========================================================================
            ...
            sage: len(results['tests'])
            2
            sage: 
            sage: # Cleanup
            sage: os.unlink(temp_file)
        """
        import numpy as np
        
        # Validate tests string
        if len(tests) != 15:
            raise ValueError("tests parameter must be exactly 15 characters (e.g., '111111111111111')")
        
        # Map test positions to test names
        test_map = [
            'frequency',                    # Position 1
            'block_frequency',              # Position 2
            'cumulative_sums',              # Position 3
            'runs',                         # Position 4
            'longest_run',                  # Position 5
            'rank',                         # Position 6
            'dft',                          # Position 7
            'non_overlapping_template',     # Position 8
            'overlapping_template',         # Position 9
            'universal',                    # Position 10
            'approximate_entropy',          # Position 11
            'random_excursions',            # Position 12
            'random_excursions_variant',    # Position 13
            'serial',                       # Position 14
            'linear_complexity'             # Position 15
        ]
        
        # Select tests based on the tests string
        selected_tests = [test_map[i] for i, bit in enumerate(tests) if bit == '1']
        
        if not selected_tests:
            raise ValueError("At least one test must be selected (tests string must contain at least one '1')")
        
        # Normalize input_format
        if input_format in [0, '0', 'ascii', 'ASCII']:
            input_format_display = 'ASCII'
            input_format = 'ascii'
        elif input_format in [1, '1', 'binary', 'BINARY', 'bin']:
            input_format_display = 'Binary'
            input_format = 'binary'
        else:
            raise ValueError(f"input_format must be 'ascii' (0) or 'binary' (1), got: {input_format}")
        
        # Print configuration summary (matching NIST STS assess binary output)
        print()
        print("=" * 72)
        print("NIST Statistical Test Suite - Python Implementation")
        print("=" * 72)
        print("Configuration:")
        print(f"  Bitstream length      : {bit_length}")
        print(f"  Number of bitstreams  : {num_sequences}")
        print(f"  Input format          : {input_format_display}")
        print(f"  Input file            : {file_path}")
        print(f"  Test selection        : {tests}")
        print()
        print("Test Parameters:")
        print(f"  Block Frequency block length       : {block_frequency_block_size}")
        print(f"  NonOverlapping Template block len  : {non_overlapping_template_block_size}")
        print(f"  Overlapping Template block length  : {overlapping_template_block_size}")
        print(f"  Approximate Entropy block length   : {approximate_entropy_block_size}")
        print(f"  Serial block length                : {serial_block_size}")
        print(f"  Linear Complexity sequence length  : {linear_complexity_block_size}")
        print()
        print("Selected Tests:")
        test_names_display = [
            "Frequency", "Block Frequency", "Cumulative Sums", "Runs",
            "Longest Run", "Rank", "DFT", "NonOverlapping Template",
            "Overlapping Template", "Universal", "Approximate Entropy",
            "Random Excursions", "Random Excursions Variant", "Serial", "Linear Complexity"
        ]
        for i, test_name in enumerate(test_names_display):
            if tests[i] == '1':
                print(f"  [{i+1:02d}] {test_name}")
        print("=" * 72)
        print()
        
        # Calculate total bits needed
        total_bits = bit_length * num_sequences
        
        # Read the file
        if input_format == 'ascii':
            # ASCII format: read as text, each '0' or '1' is one bit
            with open(file_path, 'r') as f:
                ascii_data = f.read().replace('\n', '').replace(' ', '')
                if len(ascii_data) < total_bits:
                    raise ValueError(f"File contains {len(ascii_data)} bits, but {total_bits} bits required "
                                   f"({bit_length} bits/sequence × {num_sequences} sequences)")
                # Take only what we need
                ascii_data = ascii_data[:total_bits]
                # Convert to binary array
                full_binary = np.array([int(b) for b in ascii_data], dtype=np.uint8)
        else:
            # Binary format: read as bytes, unpack bits
            with open(file_path, 'rb') as f:
                byte_data = f.read()

            bytes_per_sequence = (bit_length + 7) // 8
            padded_bytes_per_sequence = ((bit_length + 31) // 32) * 4
            expected_bytes = bytes_per_sequence * num_sequences
            padded_expected_bytes = padded_bytes_per_sequence * num_sequences

            if len(byte_data) < expected_bytes:
                raise ValueError(f"File contains {len(byte_data) * 8} bits, but {total_bits} bits required "
                               f"({bit_length} bits/sequence × {num_sequences} sequences)")

            sequences = []
            if (padded_bytes_per_sequence > bytes_per_sequence and
                    len(byte_data) == padded_expected_bytes):
                for i in range(num_sequences):
                    start = i * padded_bytes_per_sequence
                    end = start + padded_bytes_per_sequence
                    chunk = byte_data[start:end]
                    bits = np.unpackbits(np.frombuffer(chunk, dtype=np.uint8))
                    sequences.append(bits[:bit_length])
            else:
                # Unpack to bits
                full_binary = np.unpackbits(np.frombuffer(byte_data, dtype=np.uint8))
                if len(full_binary) < total_bits:
                    raise ValueError(f"File contains {len(full_binary)} bits, but {total_bits} bits required "
                                   f"({bit_length} bits/sequence × {num_sequences} sequences)")
                # Take only what we need
                full_binary = full_binary[:total_bits]
                for i in range(num_sequences):
                    start_idx = i * bit_length
                    end_idx = start_idx + bit_length
                    sequences.append(full_binary[start_idx:end_idx])

        if input_format == 'ascii':
            # Split into sequences for ASCII format
            sequences = []
            for i in range(num_sequences):
                start_idx = i * bit_length
                end_idx = start_idx + bit_length
                sequences.append(full_binary[start_idx:end_idx])
        
        # Run tests with specified parameters
        results = NISTTests.run_all_tests(
            sequences=sequences,
            test_names=selected_tests,
            alpha=alpha,
            block_frequency_block_size=block_frequency_block_size,
            non_overlapping_template_block_size=non_overlapping_template_block_size,
            overlapping_template_block_size=overlapping_template_block_size,
            approximate_entropy_block_size=approximate_entropy_block_size,
            serial_block_size=serial_block_size,
            linear_complexity_block_size=linear_complexity_block_size
        )
        
        # Format and print results in NIST-STS style
        formatted_output = NISTTests.format_results_nist_style(results)
        print(formatted_output)
        
        print("\nTests completed successfully.")
        
        return results

