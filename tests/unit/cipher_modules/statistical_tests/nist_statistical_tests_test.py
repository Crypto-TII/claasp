"""
Unit tests for NIST Statistical Tests module.

Test Coverage:
--------------
1. Core functionality tests:
    - test_run_nist_statistical_tests_tool: Tests Python-based NIST test execution

2. Dataset type tests:
   - test_run_avalanche_nist_statistics_test: Avalanche dataset
   - test_run_correlation_nist_statistics_test: Correlation dataset
   - test_run_random_nist_statistics_test: Random dataset
   - test_run_low_density_nist_statistics_test: Low density dataset
   - test_run_high_density_nist_statistics_test: High density dataset
   - test_run_CBC_nist_statistics_test: CBC dataset (with small parameters)
"""

import os
import sys
import shutil
from io import StringIO
import pytest
import numpy as np
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests


@pytest.fixture(scope="function", autouse=True)
def cleanup_test_reports():
    """Fixture to clean up test_reports folder and chart PNG files after each test."""
    yield
    if os.path.exists('test_reports'):
        shutil.rmtree('test_reports')

    import glob
    for png_file in glob.glob('nist_*_toy_cipher*.png'):
        try:
            os.remove(png_file)
        except OSError:
            pass


def test_run_nist_statistical_tests_tool():
    binary_data = np.random.randint(0, 2, 100000, dtype=np.uint8)
    result = NISTStatisticalTests._run_nist_statistical_tests_tool(
        binary_data, 10000, 10, 0, statistical_test_option_list='1' + 14 * '0')

    assert isinstance(result, dict)
    assert 'randomness_test' in result
    assert 'passed_tests' in result
    assert 'number_of_sequences_threshold' in result
    assert len(result['randomness_test']) > 0
    assert result['randomness_test'][0]['total_seqs'] == 10
    assert result['randomness_test'][0]['passed_seqs'] <= 10

    byte_data = np.random.randint(0, 256, 12500, dtype=np.uint8)
    result_bytes = NISTStatisticalTests._run_nist_statistical_tests_tool(
        byte_data, 10000, 10, 1, statistical_test_option_list='1' + 14 * '0')

    assert isinstance(result_bytes, dict)
    assert result_bytes['randomness_test'][0]['total_seqs'] == 10

    try:
        small_data = np.random.randint(0, 2, 5000, dtype=np.uint8)
        NISTStatisticalTests._run_nist_statistical_tests_tool(
            small_data, 10000, 10, 0, statistical_test_option_list='1' + 14 * '0')
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Insufficient data" in str(e)


def test_run_avalanche_nist_statistics_test():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=10))
    result = tests.nist_statistical_tests('avalanche',
                                          bits_in_one_sequence=10000,
                                          number_of_sequences=10,
                                          statistical_test_option_list='1'+14 * '0')
    assert sorted(result.keys()) == ['execution_times', 'input_parameters', 'test_results']
    assert result['input_parameters']['test_type'] == 'avalanche'
    assert result['input_parameters']['bits_in_one_sequence'] == 10000
    assert result['input_parameters']['number_of_sequences'] == 10
    freq_round0 = result['test_results'][0]['randomness_test'][0]
    assert freq_round0['test_name'] == 'Frequency'
    assert isinstance(freq_round0['p-value'], float)
    assert isinstance(freq_round0['passed'], bool)


def test_run_correlation_nist_statistics_test():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    result = tests.nist_statistical_tests('correlation',
                                          bits_in_one_sequence=10000,
                                          number_of_sequences=10,
                                          statistical_test_option_list='1'+14 * '0')
    assert sorted(result.keys()) == ['execution_times', 'input_parameters', 'test_results']
    assert result['input_parameters']['test_type'] == 'correlation'
    assert result['input_parameters']['bits_in_one_sequence'] == 10000
    assert result['input_parameters']['number_of_sequences'] == 10
    freq_round0 = result['test_results'][0]['randomness_test'][0]
    assert freq_round0['test_name'] == 'Frequency'
    assert isinstance(freq_round0['p-value'], float)
    assert isinstance(freq_round0['passed'], bool)


@pytest.mark.skip("Takes too long")
def test_run_cbc_nist_statistics_test():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    result = tests.nist_statistical_tests('cbc',  statistical_test_option_list='1'+14 * '0')
    assert sorted(result.keys()) == ['execution_times', 'input_parameters', 'test_results']
    assert result['input_parameters']['test_type'] == 'cbc'


def test_run_cbc_nist_statistics_test_small():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    result = tests.nist_statistical_tests('cbc',
                                          bits_in_one_sequence=1024,
                                          number_of_sequences=10,
                                          statistical_test_option_list='1'+14 * '0')
    assert sorted(result.keys()) == ['execution_times', 'input_parameters', 'test_results']
    assert result['input_parameters']['test_type'] == 'cbc'
    assert result['input_parameters']['bits_in_one_sequence'] == 1024
    assert result['input_parameters']['number_of_sequences'] == 10
    freq_round0 = result['test_results'][0]['randomness_test'][0]
    assert freq_round0['test_name'] == 'Frequency'
    assert isinstance(freq_round0['p-value'], float)
    assert isinstance(freq_round0['passed'], bool)


def test_run_random_nist_statistics_test():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    result = tests.nist_statistical_tests('random',
                                          bits_in_one_sequence=10000,
                                          number_of_sequences=10,
                                          statistical_test_option_list='1'+14 * '0')
    assert sorted(result.keys()) == ['execution_times', 'input_parameters', 'test_results']
    assert result['input_parameters']['test_type'] == 'random'
    assert result['input_parameters']['bits_in_one_sequence'] == 10000
    assert result['input_parameters']['number_of_sequences'] == 10
    freq_round0 = result['test_results'][0]['randomness_test'][0]
    assert freq_round0['test_name'] == 'Frequency'
    assert isinstance(freq_round0['p-value'], float)
    assert isinstance(freq_round0['passed'], bool)


def test_run_low_density_nist_statistics_test():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    result = tests.nist_statistical_tests('low_density',
                                          bits_in_one_sequence=10000,
                                          number_of_sequences=10,
                                          statistical_test_option_list='1'+14 * '0')
    assert sorted(result.keys()) == ['execution_times', 'input_parameters', 'test_results']
    assert result['input_parameters']['test_type'] == 'low_density'
    assert result['input_parameters']['bits_in_one_sequence'] == 10000
    assert result['input_parameters']['number_of_sequences'] == 10
    freq_round0 = result['test_results'][0]['randomness_test'][0]
    assert freq_round0['test_name'] == 'Frequency'
    assert isinstance(freq_round0['p-value'], float)
    assert isinstance(freq_round0['passed'], bool)


def test_run_high_density_nist_statistics_test():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    result = tests.nist_statistical_tests('high_density',
                                          bits_in_one_sequence=10000,
                                          number_of_sequences=10,
                                          statistical_test_option_list='1'+14 * '0')
    assert sorted(result.keys()) == ['execution_times', 'input_parameters', 'test_results']
    assert result['input_parameters']['test_type'] == 'high_density'
    assert result['input_parameters']['bits_in_one_sequence'] == 10000
    assert result['input_parameters']['number_of_sequences'] == 10
    freq_round0 = result['test_results'][0]['randomness_test'][0]
    assert freq_round0['test_name'] == 'Frequency'
    assert isinstance(freq_round0['p-value'], float)
    assert isinstance(freq_round0['passed'], bool)


def test_format_test_result():
    test_result = {'passed': True, 'p_value': 0.5}
    formatted = NISTStatisticalTests._format_test_result('Frequency', test_result, 1, 10)
    assert formatted['test_id'] == 1
    assert formatted['test_name'] == 'Frequency'
    assert formatted['passed'] is True
    assert formatted['p-value'] == 0.5

    test_result = {'passed': True, 'p_value1': 0.3}
    formatted = NISTStatisticalTests._format_test_result('Serial', test_result, 186, 10)
    assert formatted['p-value'] == 0.3

    test_result = {'passed': True, 'p_values': [0.1, 0.2, 0.3]}
    formatted = NISTStatisticalTests._format_test_result('RandomExcursions', test_result, 160, 10)
    assert 0 <= formatted['p-value'] <= 1


def test_run_cumsum_both_modes():
    binary_data = np.random.randint(0, 2, 1000, dtype=np.uint8)
    results = NISTStatisticalTests._run_cumsum_both_modes(binary_data)
    assert isinstance(results, list)
    assert len(results) == 2
    assert 'p_value' in results[0]
    assert 'p_value' in results[1]


def test_invalid_test_type():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result

    nist_result = tests.nist_statistical_tests('invalid_type',
                                               bits_in_one_sequence=10000,
                                               number_of_sequences=10)
    sys.stdout = old_stdout
    assert nist_result is None or 'test_results' not in nist_result


def test_multiple_statistical_tests():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=1))

    result = tests.nist_statistical_tests('random',
                                          bits_in_one_sequence=10000,
                                          number_of_sequences=10,
                                          statistical_test_option_list='1111000000000000')
    assert result is not None
    assert 'test_results' in result
    assert len(result['test_results']) > 0


def test_multiple_rounds():
    tests = NISTStatisticalTests(SimonBlockCipher(number_of_rounds=3))

    nist_result = tests.nist_statistical_tests('random',
                                               bits_in_one_sequence=10000,
                                               number_of_sequences=10,
                                               round_start=0,
                                               round_end=2,
                                               statistical_test_option_list='1'+14*'0')
    assert nist_result is not None
    assert 'test_results' in nist_result
    assert len(nist_result['test_results']) == 2
