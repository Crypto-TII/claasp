from claasp.cipher_modules.continuous_tests import ContinuousDiffusionAnalysis
from claasp.cipher_modules.report import Report
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_continuous_tests():
    speck = SpeckBlockCipher(number_of_rounds=1)
    cda = ContinuousDiffusionAnalysis(speck)
    cda_for_repo = cda.continuous_diffusion_tests()
    test_results = cda_for_repo['test_results']
    assert test_results['plaintext']['cipher_output']['continuous_neutrality_measure'][0]['values'][0] > 0.01


def test_continuous_tests_report():
    speck = SpeckBlockCipher(number_of_rounds=2)
    cda = ContinuousDiffusionAnalysis(speck)
    cda_for_repo = cda.continuous_diffusion_tests()
    cda_repo = Report(speck, cda_for_repo)
    cda_repo.print_report()
