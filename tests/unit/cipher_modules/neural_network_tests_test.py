import pytest
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.neural_network_tests import NeuralNetworkTests

def test_find_good_input_difference_for_neural_distinguisher():
    cipher = SpeckBlockCipher()
    diff, scores, highest_round = NeuralNetworkTests(cipher).find_good_input_difference_for_neural_distinguisher([True, False],
                                                                                      verbose=False,
                                                                                      number_of_generations=5)

    assert str(type(diff)) == "<class 'numpy.ndarray'>"
    assert str(type(scores)) == "<class 'numpy.ndarray'>"

def test_neural_staged_training():
    cipher = SpeckBlockCipher()
    input_differences = [0x400000, 0]
    data_generator = lambda nr, samples: NeuralNetworkTests(cipher).get_differential_dataset(input_differences, number_of_rounds = nr, samples = samples)
    neural_network = NeuralNetworkTests(cipher).get_neural_network('gohr_resnet', input_size = 64, word_size = 16)
    results_gohr = NeuralNetworkTests(cipher).train_neural_distinguisher(data_generator, starting_round = 5, neural_network = neural_network, training_samples = 10**5, testing_samples = 10**5, epochs = 1)
    assert results_gohr[5] >= 0
    neural_network = NeuralNetworkTests(cipher).get_neural_network('dbitnet', input_size = 64)
    results_dbitnet = NeuralNetworkTests(cipher).train_neural_distinguisher(data_generator, starting_round = 5, neural_network = neural_network, training_samples = 10**5, testing_samples = 10**5, epochs = 1)
    assert results_dbitnet[5] >= 0

def test_train_gohr_neural_distinguisher():
    cipher = SpeckBlockCipher()
    input_differences = [0x400000, 0]
    number_of_rounds = 5
    result = NeuralNetworkTests(cipher).train_gohr_neural_distinguisher(input_differences, number_of_rounds,
            word_size=16, number_of_epochs=1, training_samples = 10**3, testing_samples = 10**3)
    assert result[5] > 0

def test_run_autond_pipeline():
    cipher = SpeckBlockCipher()
    result = NeuralNetworkTests(cipher).run_autond_pipeline(optimizer_samples=10 ** 3, optimizer_generations=1,
                            training_samples=10 ** 2, testing_samples=10 ** 2, number_of_epochs=1, verbose=False)
    assert not result is {}

def test_get_differential_dataset():
    diff_value_plain_key = [0x400000, 0]
    cipher = SpeckBlockCipher()
    x, y = NeuralNetworkTests(cipher).get_differential_dataset(diff_value_plain_key, 5, samples=10)
    assert x.shape == (10, 64)
    assert y.shape == (10, )

@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_neural_network_blackbox_distinguisher_tests():
    cipher = SpeckBlockCipher(number_of_rounds=5)
    results = NeuralNetworkTests(cipher).neural_network_blackbox_distinguisher_tests(nb_samples=10)
    assert results['input_parameters'] == {'number_of_samples': 10, 'hidden_layers': [32, 32, 32], 'number_of_epochs': 10, 'test_name': 'neural_network_blackbox_distinguisher_tests'}


def test_neural_network_differential_distinguisher_tests():
    cipher = SpeckBlockCipher(number_of_rounds=5)
    results = NeuralNetworkTests(cipher).neural_network_differential_distinguisher_tests(nb_samples=10)
    assert results['input_parameters'] == {'test_name': 'neural_network_differential_distinguisher_tests',
            'number_of_samples': 10,
            'input_differences':  [[4194304], [10]],
            'hidden_layers': [32, 32, 32],
            'min_accuracy_value': 0,
            'max_accuracy_value': 1,
            'output_bit_size': 32,
            'number_of_epochs': 10,
            'plaintext_input_bit_size': 32,
            'key_input_bit_size': 64}
