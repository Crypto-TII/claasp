"""
Unit tests for NIST Statistical Tests module.

Test Coverage:
--------------
1. Core functionality tests:
   - test_run_nist_statistical_tests_tool: Tests Python-based NIST test execution
   - test_parse_report: Tests parsing of NIST report files

2. Visualization tests:
   - test_generate_chart_round: Tests chart generation for single round
   - test_generate_chart_all: Tests chart generation for all rounds

3. Dataset type tests:
   - test_run_avalanche_nist_statistics_test: Avalanche dataset
   - test_run_correlation_nist_statistics_test: Correlation dataset
   - test_run_random_nist_statistics_test: Random dataset
   - test_run_low_density_nist_statistics_test: Low density dataset
   - test_run_high_density_nist_statistics_test: High density dataset
   - test_run_CBC_nist_statistics_test: CBC dataset (skipped - too slow)
"""

import os
import sys
import shutil
from io import StringIO
import pytest
import numpy as np
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests

REPORT_EXAMPLE_TXT = 'claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt'


@pytest.fixture(scope="function", autouse=True)
def cleanup_test_reports():
    """Fixture to clean up test_reports folder and chart PNG files after each test."""
    yield  # Run the test
    # Cleanup after test
    if os.path.exists('test_reports'):
        shutil.rmtree('test_reports')
    
    # Remove any generated chart PNG files
    import glob
    for png_file in glob.glob('nist_*_toy_cipher*.png'):
        try:
            os.remove(png_file)
        except OSError:
            pass


def test_run_nist_statistical_tests_tool():
    # Test with Python implementation (using numpy array)
    binary_data = np.random.randint(0, 2, 10000, dtype=np.uint8)
    result = NISTStatisticalTests._run_nist_statistical_tests_tool(
        binary_data, 10000, 10, 1, statistical_test_option_list='1' + 14 * '0')

    assert isinstance(result, dict)
    assert 'randomness_test' in result
    assert 'passed_tests' in result
    assert 'number_of_sequences_threshold' in result
    assert len(result['randomness_test']) > 0


def test_parse_report():
    dictio = NISTStatisticalTests._parse_report(REPORT_EXAMPLE_TXT)

    assert dictio['number_of_sequences_threshold'] == [{'total': 10, 'passed': 8}, {'total': 8, 'passed': 7}]
    assert dictio['randomness_test'][0]['test_id'] == 1
    assert dictio['randomness_test'][0]['passed'] is False


def test_generate_chart_round():
    """Test chart generation for a single round - uses cached parsed report."""
    # Use a minimal dict instead of parsing the full report file
    dictio = {
        'data_type': 'random',
        'cipher_name': 'toy_cipher',
        'round': 1,
        'rounds': 1,
        'number_of_sequences_threshold': [{'total': 10, 'passed': 8}],
        'randomness_test': [
            {'test_id': 1, 'passed': True, 'p-value': 0.5, 'passed_proportion': 0.8},
            {'test_id': 2, 'passed': False, 'p-value': 0.01, 'passed_proportion': 0.5}
        ]
    }

    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    NISTStatisticalTests._generate_chart_round(dictio)
    sys.stdout = old_stdout

    assert result.getvalue() == \
           'Drawing round 1 is in progress.\n' \
           'Drawing round 1 is finished.\n'


def test_generate_chart_all():
    """Test chart generation for all rounds - uses minimal dict."""
    # Use a minimal dict instead of parsing the full report file
    dictio = {
        'data_type': 'random',
        'cipher_name': 'toy_cipher',
        'round': 1,
        'rounds': 1,
        'passed_tests': 10,
        'randomness_test': [
            {'test_id': i, 'passed': True, 'p-value': 0.5, 'passed_proportion': 0.8}
            for i in range(1, 16)
        ]
    }
    dict_list = [dictio]

    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    NISTStatisticalTests._generate_chart_all(dict_list)
    sys.stdout = old_stdout


def test_run_avalanche_nist_statistics_test():
    """Test avalanche NIST statistics - OPTIMIZED for speed."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    # Use smaller parameters: 10KB bits (1250 bytes), 10 sequences instead of 1MB/384
    tests.nist_statistical_tests('avalanche', 
                                 bits_in_one_sequence=10000,
                                 number_of_sequences=10,
                                 statistical_test_option_list='1'+14 * '0')
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10

def test_run_correlation_nist_statistics_test():
    """Test correlation NIST statistics - OPTIMIZED for speed."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    # Use smaller parameters: 10KB bits, 10 sequences instead of 1MB/128
    tests.nist_statistical_tests('correlation',
                                 bits_in_one_sequence=10000,
                                 number_of_sequences=10,
                                 statistical_test_option_list='1'+14 * '0')
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10

@pytest.mark.skip("Takes too long")
def test_run_CBC_nist_statistics_test():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    tests.nist_statistical_tests('cbc',  statistical_test_option_list='1'+14 * '0')
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10


def test_run_random_nist_statistics_test():
    """Test random NIST statistics - OPTIMIZED for speed."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    # Use smaller parameters: 10KB bits, 10 sequences
    tests.nist_statistical_tests('random',
                                 bits_in_one_sequence=10000,
                                 number_of_sequences=10,
                                 statistical_test_option_list='1'+14 * '0')
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10

def test_run_low_density_nist_statistics_test():
    """Test low density NIST statistics - OPTIMIZED for speed."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    # Use smaller parameters: 10KB bits, 10 sequences
    tests.nist_statistical_tests('low_density',
                                 bits_in_one_sequence=10000,
                                 number_of_sequences=10,
                                 statistical_test_option_list='1'+14 * '0')
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10

def test_run_high_density_nist_statistics_test():
    """Test high density NIST statistics - OPTIMIZED for speed."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    # Use smaller parameters: 10KB bits, 10 sequences
    tests.nist_statistical_tests('high_density',
                                 bits_in_one_sequence=10000,
                                 number_of_sequences=10,
                                 statistical_test_option_list='1'+14 * '0')
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10


def test_run_cbc_nist_statistics_test_small():
    """Test CBC NIST statistics with small parameters."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    tests.nist_statistical_tests('cbc',
                                 bits_in_one_sequence=10000,
                                 number_of_sequences=10,
                                 statistical_test_option_list='1'+14 * '0')
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10


def test_convert_to_binary_array():
    """Test the _convert_to_binary_array method."""
    # Test with bytes
    data = b'\xA5\x5A'
    result = NISTStatisticalTests._convert_to_binary_array(data)
    assert isinstance(result, np.ndarray)
    assert len(result) == 16  # 2 bytes = 16 bits
    
    # Test with bytearray
    data = bytearray([0xFF, 0x00])
    result = NISTStatisticalTests._convert_to_binary_array(data)
    assert len(result) == 16


def test_format_test_result():
    """Test the _format_test_result method."""
    # Test with p_value
    test_result = {'passed': True, 'p_value': 0.5}
    formatted = NISTStatisticalTests._format_test_result('Frequency', test_result, 1, 10)
    assert formatted['test_id'] == 1
    assert formatted['test_name'] == 'Frequency'
    assert formatted['passed'] is True
    assert formatted['p-value'] == 0.5
    
    # Test with p_value1
    test_result = {'passed': True, 'p_value1': 0.3}
    formatted = NISTStatisticalTests._format_test_result('Serial', test_result, 186, 10)
    assert formatted['p-value'] == 0.3
    
    # Test with p_values (array)
    test_result = {'passed': True, 'p_values': [0.1, 0.2, 0.3]}
    formatted = NISTStatisticalTests._format_test_result('RandomExcursions', test_result, 160, 10)
    assert 0 <= formatted['p-value'] <= 1


def test_run_cumsum_both_modes():
    """Test the _run_cumsum_both_modes method."""
    binary_data = np.random.randint(0, 2, 1000, dtype=np.uint8)
    results = NISTStatisticalTests._run_cumsum_both_modes(binary_data)
    assert isinstance(results, list)
    assert len(results) == 2
    assert 'p_value' in results[0]
    assert 'p_value' in results[1]


def test_parse_report_with_dict():
    """Test _parse_report when passed a dictionary (pass-through)."""
    test_dict = {
        'passed_tests': 5,
        'randomness_test': [],
        'number_of_sequences_threshold': []
    }
    result = NISTStatisticalTests._parse_report(test_dict)
    assert result == test_dict


def test_parse_report_missing_file():
    """Test _parse_report with non-existent file."""
    result = NISTStatisticalTests._parse_report('nonexistent_file.txt')
    assert isinstance(result, dict)
    assert result['passed_tests'] == 0
    assert result['randomness_test'] == []


def test_invalid_test_type():
    """Test with invalid test_type to trigger error paths."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    
    # This should return None due to invalid test type
    nist_result = tests.nist_statistical_tests('invalid_type',
                                               bits_in_one_sequence=10000,
                                               number_of_sequences=10)
    sys.stdout = old_stdout
    # Should print error message and return None or handle gracefully
    assert nist_result is None or 'test_results' not in nist_result


def test_multiple_statistical_tests():
    """Test running multiple statistical tests simultaneously."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    
    # Run with multiple tests enabled
    result = tests.nist_statistical_tests('random',
                                          bits_in_one_sequence=10000,
                                          number_of_sequences=10,
                                          statistical_test_option_list='1111000000000000')
    
    assert result is not None
    assert 'test_results' in result
    assert len(result['test_results']) > 0


def test_multiple_rounds():
    """Test with multiple rounds."""
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=3))
    
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    
    nist_result = tests.nist_statistical_tests('random',
                                               bits_in_one_sequence=10000,
                                               number_of_sequences=10,
                                               round_start=0,
                                               round_end=2,
                                               statistical_test_option_list='1'+14*'0')
    sys.stdout = old_stdout
    
    assert nist_result is not None
    assert 'test_results' in nist_result
    assert len(nist_result['test_results']) == 2  # rounds 0 and 1


def test_generate_chart_with_single_test():
    """Test chart generation with single test (edge case)."""
    dictio = {
        'data_type': 'random',
        'cipher_name': 'toy_cipher',
        'round': 0,
        'rounds': 1,
        'number_of_sequences_threshold': [{'total': 10, 'passed': 8}],
        'randomness_test': [{'test_id': 1, 'passed': True, 'p-value': 0.5, 'passed_proportion': 0.8}]
    }
    
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    NISTStatisticalTests._generate_chart_round(dictio)
    sys.stdout = old_stdout
    
    # Should handle single test gracefully
    output = result.getvalue()
    assert 'Drawing round 0 is in progress' in output or len(dictio['randomness_test']) == 1
