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
"""

import numpy as np
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

        - **dict**; contains 'p_value' and 'passed' (True if p_value >= 0.01)

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.frequency_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1
        s_obs = np.sum(2 * binary_data - 1)
        s_obs = np.abs(s_obs) / np.sqrt(n)
        p_value = spc.erfc(s_obs / np.sqrt(2))

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

        - **dict**; contains 'p_value' and 'passed'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
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
            return {'p_value': 0.0, 'passed': False}

        block_data = binary_data[:num_blocks * block_size].reshape((num_blocks, block_size))
        proportions = np.mean(block_data, axis=1)
        chi_squared = 4 * block_size * np.sum((proportions - 0.5) ** 2)
        p_value = spc.gammaincc(num_blocks / 2, chi_squared / 2)

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.cumulative_sums_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1
        x = 2 * binary_data - 1

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

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules/statistical_tests.nist_tests import NISTTests
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
            return {'p_value': 0.0, 'passed': False}

        # Count runs
        runs = np.sum(binary_data[1:] != binary_data[:-1]) + 1

        p_value = spc.erfc(np.abs(runs - 2 * n * pi * (1 - pi)) / (2 * np.sqrt(2 * n) * pi * (1 - pi)))

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
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
            return {'p_value': 0.0, 'passed': False}
        elif n < 6272:
            m = 8
            v_values = [1, 2, 3, 4]
            pi_values = [0.2148, 0.3672, 0.2305, 0.1875]
        elif n < 750000:
            m = 128
            v_values = [4, 5, 6, 7, 8, 9]
            pi_values = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
        else:
            m = 10000
            v_values = [10, 11, 12, 13, 14, 15, 16]
            pi_values = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]

        num_blocks = n // m
        frequencies = np.zeros(len(v_values) + 1)

        for i in range(num_blocks):
            block = binary_data[i * m:(i + 1) * m]
            # Find longest run of ones
            run_lengths = []
            current_run = 0
            for bit in block:
                if bit == 1:
                    current_run += 1
                else:
                    if current_run > 0:
                        run_lengths.append(current_run)
                    current_run = 0
            if current_run > 0:
                run_lengths.append(current_run)

            longest_run = max(run_lengths) if run_lengths else 0

            # Categorize the longest run
            if longest_run <= v_values[0]:
                frequencies[0] += 1
            elif longest_run >= v_values[-1]:
                frequencies[-1] += 1
            else:
                for j in range(len(v_values) - 1):
                    if v_values[j] < longest_run <= v_values[j + 1]:
                        frequencies[j + 1] += 1
                        break

        # Calculate chi-squared statistic
        chi_squared = 0
        for i in range(len(frequencies)):
            if i == 0 or i == len(frequencies) - 1:
                # For first and last categories, use cumulative probabilities
                if i == 0:
                    pi = sum(pi_values[:1]) if len(pi_values) > 0 else 0
                else:
                    pi = sum(pi_values[-1:]) if len(pi_values) > 0 else 0
            else:
                pi = pi_values[i - 1] if i - 1 < len(pi_values) else 0

            if pi > 0:
                chi_squared += (frequencies[i] - num_blocks * pi) ** 2 / (num_blocks * pi)

        p_value = spc.gammaincc((len(frequencies) - 1) / 2, chi_squared / 2)

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
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
            return {'p_value': 0.0, 'passed': False}

        # Count matrices by rank
        fm = 0  # full rank
        fm1 = 0  # rank m-1
        remainder = 0  # remaining

        for i in range(num_matrices):
            # Extract matrix
            block = binary_data[i * m * q:(i + 1) * m * q]
            matrix = block.reshape((m, q))

            # Compute rank using row reduction
            rank = np.linalg.matrix_rank(matrix)

            if rank == m:
                fm += 1
            elif rank == m - 1:
                fm1 += 1
            else:
                remainder += 1

        # Calculate chi-squared
        pi_m = 0.2888
        pi_m1 = 0.5776
        pi_remainder = 0.1336

        chi_squared = ((fm - num_matrices * pi_m) ** 2 / (num_matrices * pi_m) +
                       (fm1 - num_matrices * pi_m1) ** 2 / (num_matrices * pi_m1) +
                       (remainder - num_matrices * pi_remainder) ** 2 / (num_matrices * pi_remainder))

        p_value = np.exp(-chi_squared / 2)

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.dft_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1
        x = 2 * binary_data - 1

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

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.non_overlapping_template_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        if template is None:
            template = np.array([0, 0, 0, 0, 0, 0, 0, 0, 1], dtype=np.uint8)

        n = len(binary_data)
        m = len(template)
        num_blocks = n // block_size

        if num_blocks == 0:
            return {'p_value': 0.0, 'passed': False}

        # Expected number of template matches per block
        mu = (block_size - m + 1) / (2 ** m)
        sigma_squared = block_size * ((1 / (2 ** m)) - ((2 * m - 1) / (2 ** (2 * m))))

        w_counts = []
        for i in range(num_blocks):
            block = binary_data[i * block_size:(i + 1) * block_size]
            count = 0
            j = 0
            while j <= block_size - m:
                if np.array_equal(block[j:j + m], template):
                    count += 1
                    j += m  # Non-overlapping
                else:
                    j += 1
            w_counts.append(count)

        # Calculate chi-squared
        chi_squared = np.sum((np.array(w_counts) - mu) ** 2) / sigma_squared
        p_value = spc.gammaincc(num_blocks / 2, chi_squared / 2)

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.overlapping_template_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        if template is None:
            template = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1], dtype=np.uint8)

        n = len(binary_data)
        m = len(template)
        num_blocks = n // block_size

        if num_blocks == 0:
            return {'p_value': 0.0, 'passed': False}

        # Theoretical values for m=9
        lambda_val = (block_size - m + 1) / (2 ** m)
        eta = lambda_val / 2

        # Probabilities for different occurrence counts (for m=9)
        pi = [0.364091, 0.185659, 0.139381, 0.100571, 0.0704323, 0.139865]

        v_counts = [0] * 6

        for i in range(num_blocks):
            block = binary_data[i * block_size:(i + 1) * block_size]
            count = 0
            for j in range(block_size - m + 1):
                if np.array_equal(block[j:j + m], template):
                    count += 1

            # Categorize count
            if count <= 4:
                v_counts[count] += 1
            else:
                v_counts[5] += 1

        # Calculate chi-squared
        chi_squared = 0
        for i in range(6):
            chi_squared += (v_counts[i] - num_blocks * pi[i]) ** 2 / (num_blocks * pi[i])

        p_value = spc.gammaincc(5 / 2, chi_squared / 2)

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
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
            return {'p_value': 0.0, 'passed': False}
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

        # Initialize table
        T = {}

        # Initialization: process first Q blocks
        for i in range(Q):
            block = binary_data[i * L:(i + 1) * L]
            pattern = int(''.join(map(str, block)), 2)
            T[pattern] = i + 1

        # Test: process remaining K blocks
        sum_log = 0.0
        for i in range(Q, Q + K):
            block = binary_data[i * L:(i + 1) * L]
            pattern = int(''.join(map(str, block)), 2)

            if pattern in T:
                distance = i + 1 - T[pattern]
            else:
                distance = i + 1

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

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
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
            # Count overlapping patterns
            pattern_counts = {}
            for i in range(n):
                pattern = tuple(augmented[i:i + m_val])
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

            # Calculate phi
            phi = 0.0
            for count in pattern_counts.values():
                if count > 0:
                    phi += count * np.log(count / n)
            return phi / n

        phi_m = calculate_phi(m)
        phi_m_plus_1 = calculate_phi(m + 1)

        apen = phi_m - phi_m_plus_1
        chi_squared = 2 * n * (np.log(2) - apen)

        p_value = spc.gammaincc(2 ** (m - 1), chi_squared / 2)

        return {'p_value': p_value, 'passed': p_value >= 0.01}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.random_excursions_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1
        x = 2 * binary_data - 1

        # Calculate cumulative sum
        cumsum = np.concatenate(([0], np.cumsum(x), [0]))

        # Find cycles (returns to zero)
        zero_crossings = np.where(cumsum == 0)[0]
        num_cycles = len(zero_crossings) - 1

        if num_cycles < 500:
            return {'p_values': [0.0] * 8, 'passed': False}

        states = [-4, -3, -2, -1, 1, 2, 3, 4]
        p_values = []

        for x_val in states:
            # Count visits to state x_val in each cycle
            v = np.zeros(6)  # v[k] = number of cycles with exactly k visits

            for i in range(num_cycles):
                cycle = cumsum[zero_crossings[i]:zero_crossings[i + 1] + 1]
                visits = np.sum(cycle == x_val)

                if visits < 5:
                    v[visits] += 1
                else:
                    v[5] += 1

            # Theoretical probabilities
            pi_values = {
                -4: [0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000],
                -3: [0.0000, 0.0000, 0.0001, 0.0001, 0.0002, 0.0002],
                -2: [0.0000, 0.0002, 0.0011, 0.0031, 0.0060, 0.0057],
                -1: [0.0000, 0.0170, 0.0492, 0.0800, 0.0954, 0.0786],
                1: [0.0000, 0.0170, 0.0492, 0.0800, 0.0954, 0.0786],
                2: [0.0000, 0.0002, 0.0011, 0.0031, 0.0060, 0.0057],
                3: [0.0000, 0.0000, 0.0001, 0.0001, 0.0002, 0.0002],
                4: [0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000]
            }

            pi = np.array(pi_values[x_val])

            # Calculate chi-squared
            chi_squared = 0.0
            for k in range(6):
                if pi[k] > 0:
                    chi_squared += (v[k] - num_cycles * pi[k]) ** 2 / (num_cycles * pi[k])

            p_value = spc.gammaincc(5 / 2, chi_squared / 2)
            p_values.append(p_value)

        # Test passes if all p-values >= 0.01
        passed = all(p >= 0.01 for p in p_values)

        return {'p_values': p_values, 'passed': passed}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 10000, dtype=np.uint8)
            sage: result = NISTTests.random_excursions_variant_test(binary_data)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)
        # Convert to +1 and -1
        x = 2 * binary_data - 1

        # Calculate cumulative sum
        cumsum = np.concatenate(([0], np.cumsum(x), [0]))

        # Find cycles (returns to zero)
        zero_crossings = np.where(cumsum == 0)[0]
        num_cycles = len(zero_crossings) - 1

        if num_cycles < 500:
            return {'p_values': [0.0] * 18, 'passed': False}

        states = list(range(-9, 0)) + list(range(1, 10))
        p_values = []

        for x_val in states:
            # Count total occurrences of state x_val
            count = np.sum(cumsum == x_val)

            # Calculate p-value
            p_value = spc.erfc(np.abs(count - num_cycles) / np.sqrt(2 * num_cycles * (4 * abs(x_val) - 2)))
            p_values.append(p_value)

        # Test passes if all p-values >= 0.01
        passed = all(p >= 0.01 for p in p_values)

        return {'p_values': p_values, 'passed': passed}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
            sage: import numpy as np
            sage: binary_data = np.array([1, 0, 1, 1, 0, 1, 0, 1] * 1000, dtype=np.uint8)
            sage: result = NISTTests.serial_test(binary_data, m=2)
            sage: result['passed']
            True
        """
        binary_data = NISTTests._ensure_binary_array(binary_data)
        n = len(binary_data)

        # Augment the sequence
        augmented = np.concatenate([binary_data, binary_data[:m - 1]])

        def calculate_psi_squared(m_val):
            # Count overlapping patterns
            pattern_counts = {}
            for i in range(n):
                pattern = tuple(augmented[i:i + m_val])
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

            # Calculate psi_squared
            psi_squared = 0.0
            for count in pattern_counts.values():
                psi_squared += count ** 2
            psi_squared = (psi_squared * (2 ** m_val) / n) - n
            return psi_squared

        psi_m = calculate_psi_squared(m)
        psi_m_minus_1 = calculate_psi_squared(m - 1)
        psi_m_minus_2 = calculate_psi_squared(m - 2)

        delta1 = psi_m - psi_m_minus_1
        delta2 = psi_m - 2 * psi_m_minus_1 + psi_m_minus_2

        p_value1 = spc.gammaincc(2 ** (m - 1) / 2, delta1 / 2)
        p_value2 = spc.gammaincc(2 ** (m - 2) / 2, delta2 / 2)

        passed = p_value1 >= 0.01 and p_value2 >= 0.01

        return {'p_value1': p_value1, 'p_value2': p_value2, 'passed': passed}

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

            sage: from claasp.cipher_modules.statistical_tests.nist_tests import NISTTests
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
            return {'p_value': 0.0, 'passed': False}

        def berlekamp_massey(sequence):
            """Compute the linear complexity using Berlekamp-Massey algorithm."""
            n_seq = len(sequence)
            c = np.zeros(n_seq, dtype=int)
            b = np.zeros(n_seq, dtype=int)
            c[0] = 1
            b[0] = 1
            l, m, i = 0, -1, 0

            while i < n_seq:
                d = sequence[i]
                for j in range(1, l + 1):
                    d ^= c[j] & sequence[i - j]

                if d == 1:
                    t = c.copy()
                    for j in range(n_seq - i + m):
                        c[j + i - m] ^= b[j]
                    if l <= i / 2:
                        l = i + 1 - l
                        m = i
                        b = t
                i += 1
            return l

        # Expected mean
        mu = block_size / 2 + (9 + (-1) ** (block_size + 1)) / 36 - (block_size / 3 + 2 / 9) / (2 ** block_size)

        # Calculate linear complexity for each block
        t_values = np.zeros(7)  # Categories: v < -2.5, -2.5 to -1.5, ..., > 2.5

        for i in range(num_blocks):
            block = binary_data[i * block_size:(i + 1) * block_size]
            lc = berlekamp_massey(block)

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
        pi_values = [0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833]

        # Calculate chi-squared
        chi_squared = 0.0
        for i in range(7):
            chi_squared += (t_values[i] - num_blocks * pi_values[i]) ** 2 / (num_blocks * pi_values[i])

        p_value = spc.gammaincc(6 / 2, chi_squared / 2)

        return {'p_value': p_value, 'passed': p_value >= 0.01}


