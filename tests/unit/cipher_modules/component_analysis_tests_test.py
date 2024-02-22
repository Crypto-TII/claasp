from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.component_analysis_tests import generate_boolean_polynomial_ring_from_cipher
from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
from claasp.components.fsr_component import FSR
from claasp.cipher_modules.component_analysis_tests import fsr_properties
from claasp.ciphers.stream_ciphers.bluetooth_stream_cipher_e0 import BluetoothStreamCipherE0
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher


def test_generate_boolean_polynomial_ring_from_cipher():
    fancy = FancyBlockCipher(number_of_rounds=3)
    generate_boolean_polynomial_ring_from_cipher(fancy)

def test_get_all_operations():
    fancy = FancyBlockCipher(number_of_rounds=3)
    cipher_operations = CipherComponentsAnalysis(fancy).get_all_operations()
    assert list(cipher_operations.keys()) == ['sbox', 'linear_layer', 'XOR', 'AND', 'MODADD', 'ROTATE', 'SHIFT']

def test_component_analysis_tests():
    fancy = FancyBlockCipher(number_of_rounds=3)
    components_analysis = CipherComponentsAnalysis(fancy).component_analysis_tests()
    assert len(components_analysis) == 9

def test_fsr_properties():
    fsr_component = FSR(0, 0, ["input"], [[0, 1, 2, 3]], 4, [[[4, [[1, [0]], [3, [1]], [2, [2]]]]], 4])
    operation = [fsr_component, 1, ['fsr_0_0']]
    dictionary = fsr_properties(operation)
    assert dictionary['fsr_word_size'] == 4
    assert dictionary['lfsr_connection_polynomials'] == ['x^4 + (z4 + 1)*x^3 + z4*x^2 + 1']

    e0 = BluetoothStreamCipherE0(keystream_bit_len=2)
    dictionary = CipherComponentsAnalysis(e0).component_analysis_tests()
    assert dictionary[8]["number_of_registers"] == 4
    assert dictionary[8]["lfsr_connection_polynomials"][0] == 'x^25 + x^20 + x^12 + x^8 + 1'
    assert dictionary[8]["lfsr_connection_polynomials"][1] == 'x^31 + x^24 + x^16 + x^12 + 1'
    assert dictionary[8]["lfsr_connection_polynomials"][2] == 'x^33 + x^28 + x^24 + x^4 + 1'
    assert dictionary[8]["lfsr_connection_polynomials"][3] == 'x^39 + x^36 + x^28 + x^4 + 1'
    assert dictionary[8]['lfsr_polynomials_are_primitive'] == [True, True, True, True]

    triv = TriviumStreamCipher(keystream_bit_len=1)
    dictionary = CipherComponentsAnalysis(triv).component_analysis_tests()
    assert dictionary[0]["type_of_registers"] == ['non-linear', 'non-linear', 'non-linear']
