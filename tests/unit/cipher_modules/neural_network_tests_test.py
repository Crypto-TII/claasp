import pytest
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.neural_network_tests import NeuralNetworkTests

def test_find_good_input_difference_for_neural_distinguisher():
    cipher = SpeckBlockCipher()
    diff, scores, highest_round = NeuralNetworkTests(cipher).find_good_input_difference_for_neural_distinguisher([True, False],
                                                                                      verbose=False,
                                                                                      number_of_generations=1,  nb_samples=1)
    assert str(type(diff)) == "<class 'numpy.ndarray'>"
    assert str(type(scores)) == "<class 'numpy.ndarray'>"


def test_get_neural_network():
    tester = NeuralNetworkTests(None)
    gohr_net = tester.get_neural_network('gohr_resnet', input_size = 4, word_size = 1)
    assert 'keras.engine.functional.Functional' in str(type(gohr_net))
    dbitnet = tester.get_neural_network('dbitnet', input_size = 4, word_size = 1)
    assert 'keras.engine.functional.Functional' in str(type(dbitnet))

def test_neural_staged_training():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    tester = NeuralNetworkTests(cipher)
    input_differences = [0x400000, 0]
    data_generator = lambda nr, samples: NeuralNetworkTests(cipher).get_differential_dataset(input_differences, number_of_rounds = nr, samples = samples)
    neural_network = tester.get_neural_network('gohr_resnet', input_size = 64, word_size = 16, depth=1)
    results_gohr = tester.train_neural_distinguisher(data_generator, starting_round = 1, neural_network = neural_network, training_samples = 1, testing_samples = 1, epochs = 1)
    assert results_gohr[1] >= 0

def test_train_gohr_neural_distinguisher():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    input_differences = [0x400000, 0]
    number_of_rounds = 1
    result = NeuralNetworkTests(cipher).train_gohr_neural_distinguisher(input_differences, number_of_rounds,
            word_size=16, number_of_epochs=1, training_samples = 32, testing_samples = 32)
    assert result[1] >= 0

def test_run_autond_pipeline():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    result = NeuralNetworkTests(cipher).run_autond_pipeline(optimizer_samples=10, optimizer_generations=1,
                            training_samples=32, testing_samples=32, number_of_epochs=1, verbose=False)
    assert not result is {}

def test_get_differential_dataset():
    diff_value_plain_key = [0x400000, 0]
    cipher = SpeckBlockCipher(number_of_rounds=2)
    x, y = NeuralNetworkTests(cipher).get_differential_dataset(diff_value_plain_key, 1, samples=1)
    assert x.shape == (1, 64)
    assert y.shape == (1, )

@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_neural_network_blackbox_distinguisher_tests():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    results = NeuralNetworkTests(cipher).neural_network_blackbox_distinguisher_tests(nb_samples=1, number_of_epochs=1, hidden_layers = [4])
    assert results['input_parameters'] == {'cipher': cipher, 'number_of_samples': 1, 'hidden_layers': [4], 'number_of_epochs': 1, 'test_name': 'neural_network_blackbox_distinguisher_tests'}


def test_neural_network_differential_distinguisher_tests():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    results = NeuralNetworkTests(cipher).neural_network_differential_distinguisher_tests(nb_samples=1, number_of_epochs=1, hidden_layers=[4])
    assert results['input_parameters'] == {'cipher': cipher,
            'test_name': 'neural_network_differential_distinguisher_tests',
            'number_of_samples': 1,
            'input_differences':  [[4194304], [10]],
            'hidden_layers': [4],
            'min_accuracy_value': 0,
            'max_accuracy_value': 1,
            'output_bit_size': 32,
            'number_of_epochs': 1,
            'plaintext_input_bit_size': 32,
            'key_input_bit_size': 64}
