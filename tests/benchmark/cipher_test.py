import pytest
import numpy as np

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher

speck = SpeckBlockCipher()
aes = AESBlockCipher()


@pytest.mark.parametrize("number_of_samples", [10, 100, 1000, 10000])
def test_diffusion_tests_with_speck_cipher(benchmark, number_of_samples):
    benchmark(speck.diffusion_tests, number_of_samples=number_of_samples)


@pytest.mark.parametrize("number_of_samples", [10, 100, 1000, 10000])
def test_diffusion_tests_with_aes_cipher(benchmark, number_of_samples):
    benchmark(aes.diffusion_tests, number_of_samples=number_of_samples)


def test_evaluate_with_speck_cipher(benchmark):
    benchmark(speck.evaluate, [0x01234567, 0x89ABCDEF])


def test_evaluate_with_aes_cipher(benchmark):
    benchmark(aes.evaluate, [0x01234567, 0x89ABCDEF])


def test_evaluate_using_c_with_speck_cipher(benchmark):
    benchmark(speck.evaluate_using_c, [0x012345, 0x89ABCD], True)


def test_evaluate_using_c_with_aes_cipher(benchmark):
    benchmark(aes.evaluate_using_c, [0x012345, 0x89ABCD], True)


cipher_inputs_parameter_values = [[np.random.randint(256, size=(8, 2), dtype=np.uint8) for _ in range(10)],
                                  [np.random.randint(256, size=(8, 2), dtype=np.uint8) for _ in range(100)],
                                  [np.random.randint(256, size=(8, 2), dtype=np.uint8) for _ in range(10000)],
                                  [np.random.randint(256, size=(8, 2), dtype=np.uint8) for _ in range(1000000)]]


@pytest.mark.parametrize("cipher_input", cipher_inputs_parameter_values)
def test_evaluate_vectorized_with_speck_cipher(benchmark, cipher_input):
    benchmark(speck.evaluate_vectorized, cipher_input)


@pytest.mark.parametrize("cipher_input", cipher_inputs_parameter_values)
def test_evaluate_vectorized_with_aes_cipher(benchmark, cipher_input):
    benchmark(aes.evaluate_vectorized, cipher_input)


@pytest.mark.parametrize("nb_samples", [10, 100])
@pytest.mark.parametrize("hidden_layers", [[32, 32, 32], [64, 64, 64]])
@pytest.mark.parametrize("number_of_epochs", [1, 10, 100])
def test_neural_network_blackbox_distinguisher_tests_with_speck_cipher(benchmark, nb_samples,
                                                                       hidden_layers, number_of_epochs):
    benchmark(speck.neural_network_blackbox_distinguisher_tests, nb_samples, hidden_layers,
              number_of_epochs)


@pytest.mark.parametrize("nb_samples", [10, 100])
@pytest.mark.parametrize("hidden_layers", [[32, 32, 32], [64, 64, 64]])
@pytest.mark.parametrize("number_of_epochs", [1, 10, 100])
def test_neural_network_blackbox_distinguisher_tests_with_aes_cipher(benchmark, nb_samples,
                                                                     hidden_layers, number_of_epochs):
    benchmark(aes.neural_network_blackbox_distinguisher_tests, nb_samples, hidden_layers, number_of_epochs)
