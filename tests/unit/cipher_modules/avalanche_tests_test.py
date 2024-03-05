from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
from claasp.cipher_modules.avalanche_tests import AvalancheTests

def test_avalanche_probability_vectors():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    apvs = AvalancheTests(speck).avalanche_probability_vectors(100)
    assert apvs["key"]["round_output"][31][0] == [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                                                  0.0, 1.0]


def test_compute_criterion_from_avalanche_probability_vectors():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    apvs = AvalancheTests(speck).avalanche_probability_vectors(100)
    d = AvalancheTests(speck).compute_criterion_from_avalanche_probability_vectors(apvs, 0.2)
    assert d["key"]["round_output"][0][0]["avalanche_dependence_vectors"] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0]

def test_diffusion_tests():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    d = AvalancheTests(speck).avalanche_tests(number_of_samples=100)
    assert d["test_results"]["key"]["round_output"]["avalanche_dependence_vectors"][0]["vectors"][0] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    aes = AESBlockCipher(word_size=8, state_size=4, number_of_rounds=4)
    d = AvalancheTests(aes).avalanche_tests(number_of_samples=1000)
    assert d["input_parameters"]["round_key_output_avalanche_dependence_vectors_input_bit_size"] == 128

    ascon = AsconPermutation(number_of_rounds=5)
    d = AvalancheTests(ascon).avalanche_tests(number_of_samples=1000)
    assert d["input_parameters"]["cipher_output_avalanche_weight_vectors_input_bit_size"] == 320

    keccak = KeccakPermutation(number_of_rounds=5, word_size=8)
    d = AvalancheTests(keccak).avalanche_tests(number_of_samples=1000)
    assert d["input_parameters"]["round_output_avalanche_dependence_uniform_vectors_input_bit_size"] == 200