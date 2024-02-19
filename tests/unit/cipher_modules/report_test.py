from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_model import CpXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.report import Report
from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
from claasp.cipher_modules.algebraic_tests import AlgebraicTest


def test_print_report():
    speck = SpeckBlockCipher(number_of_rounds=2)
    sat = SatXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=(0,) * 32)
    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64)
    trail = sat.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])
    trail_report = Report(speck, trail)
    trail_report.print_report()

    avalanche_results = speck.diffusion_tests()
    avalanche_report = Report(speck, avalanche_results)
    avalanche_report.print_report()

    blackbox_results = speck.neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(speck, blackbox_results)
    blackbox_report.print_report()

    algebraic_results = AlgebraicTest(speck).algebraic_tests(timeout=1)
    algebraic_report = Report(speck, algebraic_results)
    algebraic_report.print_report()

    #### Adding tests for code coverage, currently not accurate as the statistical tests are not actually performed on Speck
    nist_result = StatisticalTests.run_nist_statistical_tests_tool_interactively(
        f'claasp/cipher_modules/statistical_tests/input_data_example',
        10000, 10, 1)
    parsed_result_nist = StatisticalTests.parse_report(
        f'claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt')
    nist_report = Report(speck, parsed_result_nist)
    nist_report.print_report()


def test_save_as_latex_table():
    simon = SimonBlockCipher(number_of_rounds=2)
    smt = SmtXorDifferentialModel(simon)

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=(0,) * 32)
    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64)

    trail = smt.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])

    avalanche_test_results = simon.diffusion_tests()
    avalanche_report = Report(simon, avalanche_test_results)
    avalanche_report.save_as_latex_table()

    trail_report = Report(simon, trail)
    trail_report.save_as_latex_table()


def test_save_as_DataFrame():
    speck = SpeckBlockCipher(number_of_rounds=2)
    smt = CpXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=(0,) * 32)
    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64)
    trail = smt.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])

    algebraic_results = AlgebraicTest(speck).algebraic_tests(timeout=1)
    algebraic_report = Report(speck, algebraic_results)
    algebraic_report.save_as_DataFrame()

    trail_report = Report(speck, trail)
    trail_report.save_as_DataFrame()


def test_save_as_json():
    simon = SimonBlockCipher(number_of_rounds=3)
    neural_network_blackbox_distinguisher_tests_results = simon.neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(simon, neural_network_blackbox_distinguisher_tests_results)

    milp = MilpXorDifferentialModel(simon)
    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=(0,) * 32)
    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64)

    trail = milp.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])

    trail_report = Report(simon, trail)

    algebraic_results = AlgebraicTest(simon).algebraic_tests(timeout=1)
    algebraic_report = Report(simon, algebraic_results)
    algebraic_report.save_as_json()

    trail_report.save_as_json()
    blackbox_report.save_as_json()


def test_clean_reports():
    simon = SimonBlockCipher(number_of_rounds=2)
    neural_network_blackbox_distinguisher_tests_results = simon.neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(simon, neural_network_blackbox_distinguisher_tests_results)

    blackbox_report.save_as_json()
    blackbox_report.clean_reports()
