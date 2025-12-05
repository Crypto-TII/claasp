import copy
import pickle
from pathlib import Path

from plotly.basedatatypes import BaseFigure

from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import MznXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.report import Report
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
from claasp.cipher_modules.neural_network_tests import NeuralNetworkTests
from claasp.cipher_modules.algebraic_tests import AlgebraicTests
from claasp.cipher_modules.avalanche_tests import AvalancheTests
from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
from claasp.cipher_modules.continuous_diffusion_analysis import ContinuousDiffusionAnalysis


CACHE_DIR = Path(__file__).resolve().parent / 'data'
CACHE_FILE = CACHE_DIR / 'report_test_cache.pkl'
# Heavy report fixtures are persisted to disk so subsequent test runs can
# reuse them instantly. Delete the pickle to force regeneration.
_CACHE = None


def _load_cache():
    global _CACHE
    if _CACHE is None:
        if CACHE_FILE.exists():
            with CACHE_FILE.open('rb') as cache_file:
                _CACHE = pickle.load(cache_file)
        else:
            _CACHE = {}
    return _CACHE


def _persist_cache():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with CACHE_FILE.open('wb') as cache_file:
        pickle.dump(_CACHE, cache_file)


def _get_cached_result(key, factory):
    cache = _load_cache()
    if key in cache:
        return copy.deepcopy(cache[key])
    result = factory()
    cache[key] = result
    _persist_cache()
    return copy.deepcopy(result)


def test_save_as_image(monkeypatch, tmp_path):
    captured_writes = []

    def fake_write_image(self, file, *args, **kwargs):
        captured_writes.append((file, args, kwargs))
        return None

    monkeypatch.setattr(BaseFigure, 'write_image', fake_write_image)

    output_dir = str(tmp_path / 'report-cache')
    _run_save_as_image(output_dir)

    assert captured_writes, 'Expected Plotly write_image to be invoked at least once'


def _run_save_as_image(output_dir):

    def _generate_trail_result():
        cipher = SpeckBlockCipher(number_of_rounds=2)
        sat_model = SatXorDifferentialModel(cipher)
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
        return sat_model.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])

    trail = _get_cached_result('speck_r2_sat_trail', _generate_trail_result)
    trail_report = Report(trail)
    trail_report.save_as_image(output_directory=output_dir)
    trail_report.clean_reports(output_dir=output_dir)

    def _generate_avalanche_results():
        cipher = SpeckBlockCipher(number_of_rounds=2)
        return AvalancheTests(cipher).avalanche_tests()

    avalanche_results = _get_cached_result('speck_r2_avalanche_tests', _generate_avalanche_results)
    avalanche_report = Report(avalanche_results)
    avalanche_report.save_as_image(output_directory=output_dir, test_name='avalanche_weight_vectors', fixed_input='plaintext', fixed_output='round_output',
             fixed_input_difference='average')
    avalanche_report.clean_reports(output_dir=output_dir)

    def _generate_neural_network_results():
        cipher = SpeckBlockCipher(number_of_rounds=2)
        return NeuralNetworkTests(cipher).neural_network_blackbox_distinguisher_tests(nb_samples=10)

    blackbox_results = _get_cached_result('speck_r2_neural_network_blackbox', _generate_neural_network_results)
    blackbox_report = Report(blackbox_results)
    blackbox_report.save_as_image(output_directory=output_dir)
    blackbox_report.clean_reports(output_dir=output_dir)

    def _generate_algebraic_results():
        cipher = SpeckBlockCipher(number_of_rounds=2)
        return AlgebraicTests(cipher).algebraic_tests(timeout_in_seconds=1)

    algebraic_results = _get_cached_result('speck_r2_algebraic_tests', _generate_algebraic_results)
    algebraic_report = Report(algebraic_results)
    algebraic_report.save_as_image(output_directory=output_dir)
    algebraic_report.clean_reports(output_dir=output_dir)

    def _generate_component_analysis():
        cipher = SpeckBlockCipher(number_of_rounds=2)
        return CipherComponentsAnalysis(cipher).component_analysis_tests()

    component_analysis = _get_cached_result('speck_r2_component_analysis', _generate_component_analysis)
    report_cca = Report(component_analysis)
    report_cca.save_as_image(output_directory=output_dir)
    report_cca.clean_reports(output_dir=output_dir)

    def _generate_cda_results():
        cipher = SpeckBlockCipher(number_of_rounds=2)
        cda_module = ContinuousDiffusionAnalysis(cipher)
        return cda_module.continuous_diffusion_tests()

    cda_for_repo = _get_cached_result('speck_r2_continuous_diffusion', _generate_cda_results)
    cda_repo = Report(cda_for_repo)
    cda_repo.save_as_image(output_directory=output_dir)
    cda_repo.clean_reports(output_dir=output_dir)

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
    avalanche_report.clean_reports()
    trail_report = Report(trail)
    trail_report.save_as_latex_table()
    trail_report.clean_reports()
    dieharder=DieharderTests(simon)
    report_sts = Report(dieharder.dieharder_statistical_tests('avalanche', dieharder_test_option=100))
    report_sts.save_as_latex_table()
    report_sts.clean_reports()

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
    avalanche_report.clean_reports()
    trail_report = Report(trail)
    trail_report.save_as_DataFrame()
    trail_report.clean_reports()
    dieharder = DieharderTests(speck)
    report_sts = Report(dieharder.dieharder_statistical_tests('avalanche', dieharder_test_option=100))
    report_sts.save_as_DataFrame()
    report_sts.clean_reports()

def test_save_as_json():

    speck = SpeckBlockCipher(number_of_rounds=2)

    neural_network_blackbox_distinguisher_tests_results = NeuralNetworkTests(speck).neural_network_blackbox_distinguisher_tests(nb_samples=10)
    blackbox_report = Report(neural_network_blackbox_distinguisher_tests_results)
    blackbox_report.save_as_json(fixed_input='plaintext',fixed_output='round_output')
    blackbox_report.clean_reports()

    simon = SimonBlockCipher(number_of_rounds=2)

    dieharder = DieharderTests(simon)
    report_sts = Report(dieharder.dieharder_statistical_tests('avalanche', dieharder_test_option=100))
    report_sts.save_as_json()
    report_sts.clean_reports()
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
    avalanche_report.clean_reports()

def test_show():

    speck = SpeckBlockCipher(number_of_rounds=2)
    component_analysis = CipherComponentsAnalysis(speck).component_analysis_tests()
    report_cca = Report(component_analysis)
    report_cca.show()
    avalanche_results = AvalancheTests(speck).avalanche_tests()
    avalanche_report = Report(avalanche_results)
    avalanche_report.show(test_name=None)
    avalanche_report.show(test_name='avalanche_weight_vectors', fixed_input_difference=None)
    avalanche_report.show(test_name='avalanche_weight_vectors', fixed_input_difference='average')

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
    dieharder_test_results = DieharderTests(speck).dieharder_statistical_tests('avalanche', dieharder_test_option=100)
    report_sts = Report(dieharder_test_results)
    report_sts.show()
    neural_network_test_results = NeuralNetworkTests(speck).neural_network_blackbox_distinguisher_tests(nb_samples=10)
    neural_network_tests_report = Report(neural_network_test_results)
    neural_network_tests_report.show(fixed_input_difference=None)
    neural_network_tests_report.show(fixed_input_difference='0xa')