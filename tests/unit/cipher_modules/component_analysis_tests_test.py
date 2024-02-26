from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis
from claasp.ciphers.stream_ciphers.bluetooth_stream_cipher_e0 import BluetoothStreamCipherE0
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher

def test_get_all_operations():
    fancy = FancyBlockCipher(number_of_rounds=3)
    cipher_operations = CipherComponentsAnalysis(fancy).get_all_operations()
    assert list(cipher_operations.keys()) == ['sbox', 'linear_layer', 'XOR', 'AND', 'MODADD', 'ROTATE', 'SHIFT']

def test_component_analysis_tests():
    fancy = FancyBlockCipher(number_of_rounds=3)
    components_analysis = CipherComponentsAnalysis(fancy).component_analysis_tests()
    assert len(components_analysis) == 9

    aes = AESBlockCipher(word_size=8, state_size=2, number_of_rounds=2)
    result = CipherComponentsAnalysis(aes).component_analysis_tests()
    assert len(result) == 7

@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_print_component_analysis_as_radar_charts():
    aes = AESBlockCipher(word_size=8, state_size=4, number_of_rounds=2)
    fig = CipherComponentsAnalysis(aes).print_component_analysis_as_radar_charts()
    assert str(type(fig)) == "<class 'module'>"

def test_fsr_properties():
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
