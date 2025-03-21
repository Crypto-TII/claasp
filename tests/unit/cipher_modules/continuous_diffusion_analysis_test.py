from claasp.cipher_modules.continuous_diffusion_analysis import ContinuousDiffusionAnalysis
from claasp.cipher_modules.report import Report
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_continuous_tests():
    speck = SpeckBlockCipher(number_of_rounds=1)
    cda = ContinuousDiffusionAnalysis(speck)
    cda_for_repo = cda.continuous_diffusion_tests(seed=42, number_of_processors=35)
    test_results = cda_for_repo['test_results']
    assert test_results['plaintext']['cipher_output']['continuous_neutrality_measure'][0]['values'][0] > 0.009


def test_continuous_tests_report():
    import pickle
    with open('tests/unit/cipher_modules/pre_computed_cda_obj.pkl', 'rb') as f:
        cda_for_repo = pickle.load(f)
    cda_repo = Report(cda_for_repo)
    cda_repo.save_as_image()


def test_continuous_avalanche_factor():
    aes = AESBlockCipher(number_of_rounds=5)
    cda = ContinuousDiffusionAnalysis(aes)
    result = cda.continuous_avalanche_factor(
        0.001,
        300,
        seed=43,
        number_of_processors=10
    )
    assert result['plaintext']['cipher_output']['continuous_avalanche_factor']['values'][0] > 0.1


def test_continuous_diffusion_factor():
    speck = SpeckBlockCipher(number_of_rounds=2)
    cda = ContinuousDiffusionAnalysis(speck)
    output = cda.continuous_diffusion_factor(
        5, 20, seed=42, number_of_processors=35
    )
    assert output['plaintext']['cipher_output']['diffusion_factor']['values'][0] > 0


def test_continuous_diffusion_tests():
    speck = SpeckBlockCipher(number_of_rounds=1)
    cda = ContinuousDiffusionAnalysis(speck)
    output = cda.continuous_diffusion_tests(seed=42, number_of_processors=35)["test_results"]
    assert output['plaintext']['round_key_output']['continuous_neutrality_measure'][0]["values"][0] == 0.0


def test_continuous_neutrality_measure_for_bit_j():
    speck = SpeckBlockCipher(number_of_rounds=2)
    cda = ContinuousDiffusionAnalysis(speck)
    output = cda.continuous_neutrality_measure_for_bit_j(
        30, 80, seed=42, number_of_processors=35
    )
    assert output['plaintext']['cipher_output']['continuous_neutrality_measure']["values"][0]['2'] > 0
