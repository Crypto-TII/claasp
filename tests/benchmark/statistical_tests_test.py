import pytest

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests

speck = SpeckBlockCipher()
aes = AESBlockCipher()


def test_run_avalanche_nist_statistics_test_with_speck_cipher(benchmark):
    tests = NISTStatisticalTests(speck)
    benchmark(tests.nist_statistical_tests('avalanche'), 0, 10, 10)


def test_run_avalanche_nist_statistics_test_with_aes_cipher(benchmark):
    tests = NISTStatisticalTests(aes)
    benchmark(tests.nist_statistical_tests('avalanche'), 0, 10, 10)
