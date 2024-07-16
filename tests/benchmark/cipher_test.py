import pytest
import numpy as np

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher

from claasp.cipher_modules.avalanche_tests import AvalancheTests
from claasp.cipher_modules.generic_functions_vectorized_byte import get_number_of_bytes_needed_for_bit_size


speck = SpeckBlockCipher()
aes = AESBlockCipher()


def test_evaluate_with_speck_cipher(benchmark):
    benchmark(speck.evaluate, [0x01234567, 0x89ABCDEF])


def test_evaluate_with_aes_cipher(benchmark):
    benchmark(aes.evaluate, [0x01234567, 0x89ABCDEF])


def test_evaluate_using_c_with_speck_cipher(benchmark):
    benchmark(speck.evaluate_using_c, [0x012345, 0x89ABCD], True)


def test_evaluate_using_c_with_aes_cipher(benchmark):
    benchmark(aes.evaluate_using_c, [0x012345, 0x89ABCD], True)


numbers_of_samples = [10**1, 10**2, 10**4, 10**6]
aes_inputs_byte_size = [get_number_of_bytes_needed_for_bit_size(bit_size) for bit_size in aes.inputs_bit_size]
aes_input_parameter_values = [
    [np.random.randint(256, size=(aes_inputs_byte_size[0], nb), dtype=np.uint8),
     np.random.randint(256, size=(aes_inputs_byte_size[1], nb), dtype=np.uint8)]
    for nb in numbers_of_samples]

speck_inputs_byte_size = [get_number_of_bytes_needed_for_bit_size(bit_size) for bit_size in speck.inputs_bit_size]
speck_input_parameter_values = [
    [np.random.randint(256, size=(speck_inputs_byte_size[0], nb), dtype=np.uint8),
     np.random.randint(256, size=(speck_inputs_byte_size[1], nb), dtype=np.uint8)]
    for nb in numbers_of_samples]

@pytest.mark.parametrize("cipher_input", speck_input_parameter_values)
def test_evaluate_vectorized_with_speck_cipher(benchmark, cipher_input):
    benchmark(speck.evaluate_vectorized, cipher_input)


@pytest.mark.parametrize("cipher_input", aes_input_parameter_values)
def test_evaluate_vectorized_with_aes_cipher(benchmark, cipher_input):
    benchmark(aes.evaluate_vectorized, cipher_input)


@pytest.mark.parametrize("number_of_samples", [10, 100, 1000, 10000])
def test_avalanche_tests_with_speck_cipher(benchmark, number_of_samples):
    benchmark(AvalancheTests(speck).avalanche_tests, number_of_samples=number_of_samples)


@pytest.mark.parametrize("number_of_samples", [10, 100, 1000, 10000])
def test_avalanche_tests_with_aes_cipher(benchmark, number_of_samples):
    benchmark(AvalancheTests(aes).avalanche_tests, number_of_samples=number_of_samples)
