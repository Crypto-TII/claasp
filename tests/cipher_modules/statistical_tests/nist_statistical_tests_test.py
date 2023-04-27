import os
import sys
from io import StringIO

from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests

REPORT_EXAMPLE_TXT = 'claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt'


def test_run_nist_statistical_tests_tool_interactively():
    if not os.path.exists('test_reports/statistical_tests/experiments'):
        os.makedirs('test_reports/statistical_tests/experiments')
    result = StatisticalTests.run_nist_statistical_tests_tool_interactively(
        'claasp/cipher_modules/statistical_tests/input_data_example', 10000, 10, 1)

    assert result is True


def test_parse_report():
    dictio = StatisticalTests.parse_report(REPORT_EXAMPLE_TXT)

    assert dictio['number_of_sequences_threshold'] == [{'total': 10, 'passed': 8}, {'total': 8, 'passed': 7}]
    assert dictio['randomness_test'][0]['test_id'] == 1
    assert dictio['randomness_test'][0]['passed'] is False


def test_generate_chart_round():
    dictio = StatisticalTests.parse_report(REPORT_EXAMPLE_TXT)
    dictio['data_type'] = 'random'
    dictio['cipher_name'] = 'toy_cipher'
    dictio['round'] = 1
    dictio['rounds'] = 1

    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    StatisticalTests.generate_chart_round(dictio)
    sys.stdout = old_stdout

    assert result.getvalue() == \
           'Drawing round 1 is in progress.\n' \
           'Drawing round 1 is finished.\n'


def test_generate_chart_all():
    dictio = StatisticalTests.parse_report(REPORT_EXAMPLE_TXT)
    dictio['data_type'] = 'random'
    dictio['cipher_name'] = 'toy_cipher'
    dictio['round'] = 1
    dictio['rounds'] = 1
    dict_list = [dictio]

    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    StatisticalTests.generate_chart_all(dict_list)
    sys.stdout = old_stdout

    assert result.getvalue() == \
           'Drawing chart for all rounds is in progress.\n' \
           'Drawing chart for all rounds is in finished.\n'


def test_run_avalanche_nist_statistics_test():
    tests = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    tests.run_avalanche_nist_statistics_test(0, 10, 10, round_end=2)
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10


def test_run_correlation_nist_statistics_test():
    tests = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    tests.run_correlation_nist_statistics_test(0, 10, 10, round_end=2)
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10


def test_run_CBC_nist_statistics_test():
    tests = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    tests.run_CBC_nist_statistics_test(0, 2, 2, round_end=2)
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10


def test_run_random_nist_statistics_test():
    tests = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    tests.run_random_nist_statistics_test(0, 10, 10, round_end=2)
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10


def test_run_low_density_nist_statistics_test():
    tests = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    tests.run_low_density_nist_statistics_test(0, 10, 10, round_end=2)
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10


def test_run_high_density_nist_statistics_test():
    tests = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    tests.run_high_density_nist_statistics_test(0, 10, 10, round_end=2)
    sys.stdout = old_stdout
    return_str = result.getvalue()
    assert return_str.find('Finished.') == len(return_str) - 10
