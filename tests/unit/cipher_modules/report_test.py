from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_model import CpXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.report import Report
from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests
from claasp.cipher_modules.neural_network_tests import NeuralNetworkTests
from claasp.cipher_modules.algebraic_tests import AlgebraicTests
from claasp.cipher_modules.avalanche_tests import AvalancheTests
from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis


def test_save_as_image():
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
    trail_report = Report(trail)
    trail_report.save_as_image()

    avalanche_results = AvalancheTests(speck).avalanche_tests()
    avalanche_report = Report(avalanche_results)
    avalanche_report.save_as_image()

    blackbox_results = NeuralNetworkTests(speck).neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(blackbox_results)
    blackbox_report.save_as_image()

    algebraic_results = AlgebraicTests(speck).algebraic_tests(timeout=1)
    algebraic_report = Report(algebraic_results)
    algebraic_report.save_as_image()

    component_analysis = CipherComponentsAnalysis(speck).component_analysis_tests()
    report_cca = Report(component_analysis)
    report_cca.save_as_image()

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

    avalanche_test_results = AvalancheTests(simon).avalanche_tests()
    avalanche_report = Report(avalanche_test_results)
    avalanche_report.save_as_latex_table()

    trail_report = Report(trail)
    trail_report.save_as_latex_table()

    nist = NISTStatisticalTests(simon)
    report_sts = Report(nist.nist_statistical_tests('avalanche'))
    report_sts.save_as_latex_table()


def test_save_as_DataFrame():
    speck = SpeckBlockCipher(number_of_rounds=2)
    cp = CpXorDifferentialModel(speck)
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
    trail = cp.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])

    algebraic_results = AlgebraicTests(speck).algebraic_tests(timeout=1)
    algebraic_report = Report(algebraic_results)
    algebraic_report.save_as_DataFrame()

    component_analysis = CipherComponentsAnalysis(speck).component_analysis_tests()
    report_cca = Report(component_analysis)
    report_cca.save_as_DataFrame()

    avalanche_results = AvalancheTests(speck).avalanche_tests()
    avalanche_report = Report(avalanche_results)
    avalanche_report.save_as_DataFrame()

    trail_report = Report(trail)
    trail_report.save_as_DataFrame()

    nist = NISTStatisticalTests(speck)
    report_sts = Report(nist.nist_statistical_tests('avalanche'))
    report_sts.save_as_DataFrame()


def test_save_as_json():
    simon = SimonBlockCipher(number_of_rounds=3)
    neural_network_blackbox_distinguisher_tests_results = NeuralNetworkTests(
        simon).neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(neural_network_blackbox_distinguisher_tests_results)

    nist = NISTStatisticalTests(simon)
    report_sts = Report(nist.nist_statistical_tests('avalanche'))
    report_sts.save_as_json()

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

    trail_report = Report(trail)

    algebraic_results = AlgebraicTests(simon).algebraic_tests(timeout=1)
    algebraic_report = Report(algebraic_results)
    algebraic_report.save_as_json()

    avalanche_results = AvalancheTests(simon).avalanche_tests()
    avalanche_report = Report(avalanche_results)
    avalanche_report.save_as_json()

    trail_report.save_as_json()
    blackbox_report.save_as_json()


def test_clean_reports():
    simon = SimonBlockCipher(number_of_rounds=2)
    neural_network_blackbox_distinguisher_tests_results = NeuralNetworkTests(
        simon).neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(neural_network_blackbox_distinguisher_tests_results)

    blackbox_report.save_as_json()
    blackbox_report.clean_reports()


def test_show():
    speck = SpeckBlockCipher(number_of_rounds=3)
    component_analysis = CipherComponentsAnalysis(speck).component_analysis_tests()
    report_cca = Report(component_analysis)
    report_cca.show()

    #result = NeuralNetworkTests(speck).run_autond_pipeline(optimizer_samples=10 ** 3, optimizer_generations=1,
    #                                                       training_samples=10 ** 2, testing_samples=10 ** 2,
    #                                                       number_of_epochs=1, verbose=False)
    #report_autond = Report(result)
    #report_autond.show()

    avalanche_results = AvalancheTests(speck).avalanche_tests()
    avalanche_report = Report(avalanche_results)
    avalanche_report.show(test_name=None)
    avalanche_report.show(test_name='avalanche_weight_vectors', fixed_input_difference=None)
    avalanche_report.show(test_name='avalanche_weight_vectors', fixed_input_difference='average')

    milp = MilpXorDifferentialModel(speck)
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

    trail = milp.find_one_xor_differential_trail(fixed_values=[plaintext, key])
    trail_report = Report(trail)
    trail_report.show()

    algebraic_results = AlgebraicTests(speck).algebraic_tests(timeout=1)
    algebraic_report = Report(algebraic_results)
    algebraic_report.show()

    nist = NISTStatisticalTests(speck)
    report_sts = Report(nist.nist_statistical_tests('avalanche'))
    report_sts.show()

    neural_network_tests = NeuralNetworkTests(speck).neural_network_differential_distinguisher_tests()
    neural_network_tests_report = Report(neural_network_tests)
    neural_network_tests_report.show(fixed_input_difference=None)
    neural_network_tests_report.show(fixed_input_difference='0xa')