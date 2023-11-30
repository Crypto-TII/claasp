from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.report import Report

def test_print_report():

    speck = SpeckBlockCipher(number_of_rounds=5)
    sat = SatXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id = 'plaintext',
        constraint_type = 'not_equal',
        bit_positions = range(32),
        bit_values = (0,) * 32)
    key = set_fixed_variables(
            component_id = 'key',
            constraint_type = 'equal',
            bit_positions = range(64),
            bit_values = (0,) * 64)
    trail = sat.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])
    trail_report = Report(speck, trail)
    trail_report.print_report()
def test_save_as_latex_table():

    simon = SimonBlockCipher(number_of_rounds=3)
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
    speck = SpeckBlockCipher(number_of_rounds=4)
    smt = SmtXorDifferentialModel(speck)
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

    algebraic_results = speck.algebraic_tests(timeout=1)
    algebraic_report = Report(speck, algebraic_results)
    algebraic_report.save_as_DataFrame()


    trail_report = Report(speck, trail)
    trail_report.save_as_DataFrame()

def test_save_as_json():

    simon = SimonBlockCipher(number_of_rounds=6)
    neural_network_blackbox_distinguisher_tests_results = simon.neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(simon,neural_network_blackbox_distinguisher_tests_results)

    sat = SatXorDifferentialModel(simon)
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

    trail_report = Report(simon, trail)


    trail_report.save_as_json()
    blackbox_report.save_as_json()

def test_clean_reports():

    simon = SimonBlockCipher(number_of_rounds=3)
    neural_network_blackbox_distinguisher_tests_results = simon.neural_network_blackbox_distinguisher_tests()
    blackbox_report = Report(simon, neural_network_blackbox_distinguisher_tests_results)

    blackbox_report.save_as_json()
    blackbox_report.clean_reports()