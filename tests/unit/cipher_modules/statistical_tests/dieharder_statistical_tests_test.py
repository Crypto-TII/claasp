import pytest

from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests

OUTPUT_TXT = 'dieharder_test_output.txt'
TESTS_FINISHED = "Dieharder Tests Finished!!!"
INPUT_DATA_EXAMPLE = 'claasp/cipher_modules/statistical_tests/input_data_example'
OUTPUT_TXT_IS_FINISHED = "Parsing dieharder_test_output.txt is in progress.\n" \
                          "Parsing dieharder_test_output.txt is finished."


@pytest.mark.skip("Takes to long")
def test_run_dieharder_statistical_tests_tool_interactively():
    result = DieharderTests._run_dieharder_statistical_tests_tool(INPUT_DATA_EXAMPLE)

    assert result == TESTS_FINISHED


@pytest.mark.skip("Takes to long")
def test_parse_report():
    result = DieharderTests._run_dieharder_statistical_tests_tool(INPUT_DATA_EXAMPLE)

    assert result == TESTS_FINISHED

    dictio = DieharderTests._parse_report(OUTPUT_TXT)

    assert dictio == OUTPUT_TXT_IS_FINISHED


@pytest.mark.skip("Takes to long")
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


@pytest.mark.skip("Takes to long")
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


@pytest.mark.skip("Takes to long")
def test_run_avalanche_dieharder_statistical_tests():
    dieharder = DieharderTests(SpeckBlockCipher(number_of_rounds=3))
    result = dieharder.dieharder_statistical_tests(test_type='avalanche', round_end=1)

    assert result == TESTS_FINISHED


@pytest.mark.skip("Takes to long")
def test_run_correlation_dieharder_statistics_test():
    dieharder = DieharderTests(SpeckBlockCipher(number_of_rounds=3))
    result = dieharder.dieharder_statistical_tests(test_type='correlation', round_end=1)

    assert result == TESTS_FINISHED


@pytest.mark.skip("Takes to long")
def test_run_CBC_dieharder_statistics_test():
    dieharder = DieharderTests(SpeckBlockCipher(number_of_rounds=3))
    result = dieharder.dieharder_statistical_tests(test_type='cbc', round_end=1)

    assert result == TESTS_FINISHED


@pytest.mark.skip("Takes to long")
def test_run_random_dieharder_statistics_test():
    dieharder = DieharderTests(SpeckBlockCipher(number_of_rounds=3))
    result = dieharder.dieharder_statistical_tests(test_type='random', round_end=1)

    assert result == TESTS_FINISHED


@pytest.mark.skip("Takes to long")
def test_run_low_density_dieharder_statistics_test():
    dieharder = DieharderTests(SpeckBlockCipher(number_of_rounds=3))
    result = dieharder.dieharder_statistical_tests(test_type='low_density', round_end=1)

    assert result == TESTS_FINISHED


@pytest.mark.skip("Takes to long")
def test_run_high_density_dieharder_statistics_test():
    dieharder = DieharderTests(SpeckBlockCipher(number_of_rounds=3))
    result = dieharder.dieharder_statistical_tests(test_type='high_density', round_end=1)

    assert result == TESTS_FINISHED
