from claasp.cipher_modules.algebraic_tests import AlgebraicTest
from claasp.ciphers.toys.toyspn1 import ToySPN1
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_algebraic_tests_of_cipher():

    toyspn = ToySPN1(number_of_rounds=2)
    alg_test = AlgebraicTest(toyspn)
    result=alg_test.algebraic_tests(120)  # timeout=120 seconds
    result['test_results']['test_passed']== [False, False]

    speck = SpeckBlockCipher(number_of_rounds=1)
    alg_test = AlgebraicTest(speck)
    result=alg_test.algebraic_tests(120)  # timeout=120 seconds
    result['test_results']['test_passed'] == [False]

    speck = SpeckBlockCipher(number_of_rounds=2)
    alg_test = AlgebraicTest(speck)
    result=alg_test.algebraic_tests(120)
    result['test_results']['test_passed'] == [False, False]
