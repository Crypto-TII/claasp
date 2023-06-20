from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
StatisticalTests.run_nist_statistical_tests_tool_interactively(
    90000,
    "test_BSS.dat",
    100,
    0,
    "avalanche",
    "111111111111111")

# (bit_stream_length, input_file, number_of_bit_streams,
#                                                       input_file_format, test_type,
#                                                       statistical_test_option_list=15 * '1')
# niststs 4608 test_overlapping_ascii.bin 100 0 test_reports/statistical_tests/experiments/avalanche 111111111111111 avalanche