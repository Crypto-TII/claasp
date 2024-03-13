import pytest

from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests

OUTPUT_TXT = 'dieharder_test_output.txt'
TESTS_FINISHED = "Dieharder Tests Finished!!!"
INPUT_DATA_EXAMPLE = 'claasp/cipher_modules/statistical_tests/input_data_example'
OUTPUT_TXT_IS_FINISHED = "Parsing dieharder_test_output.txt is in progress.\n" \
                          "Parsing dieharder_test_output.txt is finished."


@pytest.mark.skip("Takes to long")
def test_run_dieharder_statistical_tests_tool():
    result = DieharderTests._run_dieharder_statistical_tests_tool(INPUT_DATA_EXAMPLE)

    assert result == TESTS_FINISHED

def test_dieharder_statistical_tests():
    speck = SimonBlockCipher(number_of_rounds=3)
    dieharder_tests = DieharderTests(speck)
    dieharder_avalanche_test_results = dieharder_tests.dieharder_statistical_tests('avalanche', dieharder_test_option='100')
    dieharder_correlation_test_results = dieharder_tests.dieharder_statistical_tests('correlation', dieharder_test_option='100')
    dieharder_random_test_results = dieharder_tests.dieharder_statistical_tests('random', dieharder_test_option='100')
    dieharder_high_density_test_results = dieharder_tests.dieharder_statistical_tests('high_density', dieharder_test_option='100')
    dieharder_low_density_test_results = dieharder_tests.dieharder_statistical_tests('low_density', dieharder_test_option='100')



def test_parse_report():
    result = DieharderTests._run_dieharder_statistical_tests_tool(INPUT_DATA_EXAMPLE)

    assert result == TESTS_FINISHED

    dictio = DieharderTests._parse_report(OUTPUT_TXT)

    assert dictio == OUTPUT_TXT_IS_FINISHED


def test_generate_chart_round():
    result = DieharderTests._run_dieharder_statistical_tests_tool(INPUT_DATA_EXAMPLE)

    assert result == TESTS_FINISHED

    dictio = DieharderTests._parse_report(OUTPUT_TXT)

    assert dictio == OUTPUT_TXT_IS_FINISHED

    dictio['data_type'] = 'random'
    dictio['cipher_name'] = 'toy_cipher'
    dictio['round'] = 1
    dictio['rounds'] = 1
    chart = DieharderTests._generate_chart_round(dictio)

    assert chart == "Drawing round 1 is in progress.\n" \
                    "Drawing round 1 is finished. Please find the chart in file " \
                    "dieharder_random_toy_cipher_round_1.png."


def test_generate_chart_all():
    result = DieharderTests._run_dieharder_statistical_tests_tool(INPUT_DATA_EXAMPLE)

    assert result == TESTS_FINISHED

    dictio = DieharderTests._parse_report(OUTPUT_TXT)

    assert dictio == OUTPUT_TXT_IS_FINISHED

    dictio['data_type'] = 'random'
    dictio['cipher_name'] = 'toy_cipher'
    dictio['round'] = 1
    dictio['rounds'] = 1
    dict_list = [dictio]
    chart = DieharderTests._generate_chart_all(dict_list)

    assert chart == "Drawing chart for all rounds is in progress.\n" \
                    "Drawing chart for all rounds is in finished. Please find the chart in file " \
                    "dieharder_random_toy_cipher.png."

