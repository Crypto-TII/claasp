from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import MznXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.report import Report
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests
from claasp.cipher_modules.neural_network_tests import NeuralNetworkTests
from claasp.cipher_modules.algebraic_tests import AlgebraicTests
from claasp.cipher_modules.avalanche_tests import AvalancheTests
from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
from claasp.cipher_modules.continuous_diffusion_analysis import ContinuousDiffusionAnalysis
from sage.all import load
# from tests.precomputed_test_results import speck_three_rounds_component_analysis, speck_three_rounds_avalanche_tests, speck_three_rounds_neural_network_tests, speck_three_rounds_dieharder_tests, present_four_rounds_find_one_xor_differential_trail

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
    #trail_report.save_as_image()

    avalanche_results = AvalancheTests(speck).avalanche_tests()
    avalanche_report = Report(avalanche_results)
    #avalanche_report.save_as_image(test_name='avalanche_weight_vectors', fixed_input='plaintext', fixed_output='round_output',
    #         fixed_input_difference='average')

    blackbox_results = NeuralNetworkTests(speck).neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(blackbox_results)
    #blackbox_report.save_as_image()

    algebraic_results = AlgebraicTests(speck).algebraic_tests(timeout_in_seconds=1)
    algebraic_report = Report(algebraic_results)
    #algebraic_report.save_as_image()

    component_analysis = CipherComponentsAnalysis(speck).component_analysis_tests()
    report_cca = Report(component_analysis)
    #report_cca.save_as_image()

    speck = SpeckBlockCipher(number_of_rounds=2)
    cda = ContinuousDiffusionAnalysis(speck)
    cda_for_repo = cda.continuous_diffusion_tests()
    cda_repo = Report(cda_for_repo)
    #cda_repo.save_as_image()




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
    avalanche_report.save_as_latex_table(fixed_input='plaintext',fixed_output='round_output',fixed_test='avalanche_weight_vectors')

    trail_report = Report(trail)
    trail_report.save_as_latex_table()

    dieharder=DieharderTests(simon)
    report_sts = Report(dieharder.dieharder_statistical_tests('avalanche', dieharder_test_option=100))
    report_sts.save_as_latex_table()

def test_save_as_DataFrame():
    speck = SpeckBlockCipher(number_of_rounds=2)
    cp = MznXorDifferentialModel(speck)
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

    avalanche_results = AvalancheTests(speck).avalanche_tests()
    avalanche_report = Report(avalanche_results)
    avalanche_report.save_as_DataFrame(fixed_input='plaintext',fixed_output='round_output',fixed_test='avalanche_weight_vectors')

    trail_report = Report(trail)
    trail_report.save_as_DataFrame()

    dieharder = DieharderTests(speck)
    report_sts = Report(dieharder.dieharder_statistical_tests('avalanche', dieharder_test_option=100))
    report_sts.save_as_DataFrame()


def test_save_as_json():
    simon = SimonBlockCipher(number_of_rounds=2)

    neural_network_blackbox_distinguisher_tests_results = NeuralNetworkTests(
        simon).neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(neural_network_blackbox_distinguisher_tests_results)
    blackbox_report.save_as_json(fixed_input='plaintext',fixed_output='round_output')
    dieharder = DieharderTests(simon)
    report_sts = Report(dieharder.dieharder_statistical_tests('avalanche', dieharder_test_option=100))
    report_sts.save_as_json()

    present = PresentBlockCipher(number_of_rounds=2)
    sat = SatXorDifferentialModel(present)
    related_key_setting = [
        set_fixed_variables(component_id='key', constraint_type='not_equal', bit_positions=list(range(80)),
                            bit_values=[0] * 80),
        set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=list(range(64)),
                            bit_values=[0] * 64)
    ]
    trail = sat.find_one_xor_differential_trail_with_fixed_weight(fixed_weight=16, fixed_values=related_key_setting,
                                                                  solver_name='KISSAT_EXT')
    trail_report = Report(trail)
    trail_report.show()

    avalanche_results = AvalancheTests(simon).avalanche_tests()
    avalanche_report = Report(avalanche_results)
    avalanche_report.save_as_json(fixed_input='plaintext',fixed_output='round_output',fixed_test='avalanche_weight_vectors')


def test_show():
    precomputed_results = load('tests/precomputed_results.sobj')
    component_analysis = precomputed_results['speck_three_rounds_component_analysis']
    report_cca = Report(component_analysis)
    report_cca.show()
    avalanche_results = precomputed_results['speck_three_rounds_avalanche_test']
    avalanche_report = Report(avalanche_results)
    avalanche_report.show(test_name=None)
    avalanche_report.show(test_name='avalanche_weight_vectors', fixed_input_difference=None)
    avalanche_report.show(test_name='avalanche_weight_vectors', fixed_input_difference='average')
    trail = precomputed_results['present_four_rounds_trail_search']
    trail_report = Report(trail)
    trail_report.show()
    dieharder_test_results = precomputed_results['speck_three_rounds_dieharder_test']
    report_sts = Report(dieharder_test_results)
    report_sts.show()
    neural_network_test_results = precomputed_results['speck_three_rounds_neural_network_test']
    neural_network_tests_report = Report(neural_network_test_results)
    neural_network_tests_report.show(fixed_input_difference=None)
    neural_network_tests_report.show(fixed_input_difference='0xa')