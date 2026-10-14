import random
from unittest import mock

import numpy as np
import pytest
import tensorflow as tf

from claasp.cipher_modules import neural_network_tests
from claasp.cipher_modules.neural_network_tests import NeuralNetworkTests
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher

DBITNET_64_TRAINABLE_PARAMETERS = 296065
DBITNET_64_PARAMETERS = 298113
SYNTHETIC_SAMPLES = 4
SYNTHETIC_OUTPUT_BYTES = 2


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
    assert 'keras' in str(type(gohr_net))
    dbitnet = tester.get_neural_network('dbitnet', input_size = 4, word_size = 1)
    assert 'keras' in str(type(dbitnet))

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
    results = NeuralNetworkTests(cipher).neural_network_blackbox_distinguisher_tests(nb_samples=10, number_of_epochs=1, hidden_layers = [4])
    assert results['input_parameters'] == {'cipher': cipher, 'number_of_samples': 10, 'hidden_layers': [4], 'number_of_epochs': 1, 'test_name': 'neural_network_blackbox_distinguisher_tests'}


def test_neural_network_differential_distinguisher_tests():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    results = NeuralNetworkTests(cipher).neural_network_differential_distinguisher_tests(nb_samples=10, number_of_epochs=1, hidden_layers=[4])
    assert results['input_parameters'] == {'cipher': cipher,
            'test_name': 'neural_network_differential_distinguisher_tests',
            'number_of_samples': 10,
            'input_differences':  [[4194304], [10]],
            'hidden_layers': [4],
            'min_accuracy_value': 0,
            'max_accuracy_value': 1,
            'output_bit_size': 32,
            'number_of_epochs': 1,
            'plaintext_input_bit_size': 32,
            'key_input_bit_size': 64}


@pytest.mark.parametrize('test_method', ['neural_network_blackbox_distinguisher_tests',
                                         'neural_network_differential_distinguisher_tests'])
def test_distinguisher_tests_forward_number_of_epochs(test_method):
    sequential = mock.MagicMock()
    sequential.return_value.fit.return_value.history = {'val_binary_accuracy': [0.5]}
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=2))
    with mock.patch.object(neural_network_tests, 'Sequential', sequential):
        getattr(tester, test_method)(nb_samples=8, number_of_epochs=7, hidden_layers=[4])
    fit_calls = sequential.return_value.fit.call_args_list
    assert fit_calls
    assert all(fit_call.kwargs['epochs'] == 7 for fit_call in fit_calls)


def _mocked_training(validation_accuracies):
    neural_network = mock.Mock()
    neural_network.fit.return_value.history = {'val_acc': validation_accuracies}
    data_generator = mock.Mock(return_value=(np.zeros((4, 64), dtype=np.uint8), np.zeros(4, dtype=np.uint8)))
    return neural_network, data_generator


def _generated_rounds(data_generator):
    return sorted({generator_call.kwargs['nr'] for generator_call in data_generator.call_args_list})


def test_train_neural_distinguisher_trains_the_final_round():
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=2))
    neural_network, data_generator = _mocked_training([0.6, 0.9, 0.7])
    result = tester.train_neural_distinguisher(data_generator, starting_round=2, neural_network=neural_network,
                                               training_samples=4, testing_samples=10 ** 6, epochs=3, pipeline=False)
    assert result == {2: 0.9}
    assert _generated_rounds(data_generator) == [2]
    assert neural_network.fit.call_args.kwargs['epochs'] == 3


def test_train_neural_distinguisher_pipeline_advances_into_the_final_round():
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=2))
    neural_network, data_generator = _mocked_training([1.0])
    result = tester.train_neural_distinguisher(data_generator, starting_round=1, neural_network=neural_network,
                                               training_samples=4, testing_samples=10 ** 6, epochs=1, pipeline=True)
    assert result == {1: 1.0, 2: 1.0}
    assert _generated_rounds(data_generator) == [1, 2]


def test_train_neural_distinguisher_pipeline_stops_below_threshold():
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=2))
    neural_network, data_generator = _mocked_training([0.5])
    result = tester.train_neural_distinguisher(data_generator, starting_round=1, neural_network=neural_network,
                                               training_samples=4, testing_samples=10 ** 6, epochs=1, pipeline=True)
    assert result == {1: 0.5}


def test_train_neural_distinguisher_single_round_primitive():
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=1))
    neural_network, data_generator = _mocked_training([1.0])
    result = tester.train_neural_distinguisher(data_generator, starting_round=1, neural_network=neural_network,
                                               training_samples=4, testing_samples=10 ** 6, epochs=1, pipeline=True)
    assert result == {1: 1.0}
    assert _generated_rounds(data_generator) == [1]


@pytest.mark.parametrize('starting_round, error', [(0, ValueError), (-1, ValueError), (3, ValueError),
                                                   (1.5, TypeError), (True, TypeError), ('1', TypeError)])
def test_train_neural_distinguisher_rejects_invalid_starting_round(starting_round, error):
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=2))
    neural_network, data_generator = _mocked_training([1.0])
    with pytest.raises(error):
        tester.train_neural_distinguisher(data_generator, starting_round=starting_round,
                                          neural_network=neural_network, training_samples=4, testing_samples=4)
    data_generator.assert_not_called()


def test_train_gohr_neural_distinguisher_trains_the_final_round():
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=2))
    neural_network, _ = _mocked_training([0.8])
    with mock.patch.object(tester, 'get_neural_network', return_value=neural_network):
        result = tester.train_gohr_neural_distinguisher([0x400000, 0], 2, word_size=16, number_of_epochs=1,
                                                        training_samples=4, testing_samples=4)
    assert result == {2: 0.8}


def test_get_differential_dataset_uses_one_based_round_numbers():
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=2))
    x, y = tester.get_differential_dataset([0x400000, 0], 2, samples=4)
    assert x.shape == (4, 64)
    assert y.shape == (4,)
    with pytest.raises(ValueError):
        tester.get_differential_dataset([0x400000, 0], 0, samples=4)


def _dbitnet(input_size=64):
    return NeuralNetworkTests(None).get_neural_network('dbitnet', input_size=input_size, word_size=1)


def _trainable_parameters(model):
    return int(sum(np.prod(weight.shape) for weight in model.trainable_weights))


def test_dbitnet_construction_uses_a_rescaling_layer():
    model = _dbitnet()
    layer_types = [type(layer).__name__ for layer in model.layers]
    assert 'TFOpLambda' not in layer_types
    assert 'Lambda' not in layer_types
    assert layer_types.count('Rescaling') == 1
    assert model.input_shape == (None, 64, 1)
    assert model.output_shape == (None, 1)
    assert _trainable_parameters(model) == DBITNET_64_TRAINABLE_PARAMETERS
    assert model.count_params() == DBITNET_64_PARAMETERS


def test_dbitnet_rescaling_maps_bits_to_plus_minus_one():
    rescaling = next(layer for layer in _dbitnet().layers if type(layer).__name__ == 'Rescaling')
    bits = np.array([[[0.0], [1.0]]], dtype=np.float32)
    np.testing.assert_array_equal(np.asarray(rescaling(bits)), [[[-1.0], [1.0]]])
    values = np.random.default_rng(0).random((1, 64, 1), dtype=np.float32)
    expected = (values - np.float32(0.5)) / np.float32(0.5)
    np.testing.assert_array_equal(np.asarray(rescaling(values)), expected)


def test_dbitnet_forward_pass_on_differential_dataset():
    x, _ = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=2)).get_differential_dataset([0x400000, 0], 2,
                                                                                               samples=3)
    predictions = _dbitnet().predict(x, verbose=0)
    assert predictions.shape == (3, 1)
    assert np.all((predictions >= 0) & (predictions <= 1))


# Keras 3 cannot restore the compile configuration of legacy HDF5 files, so only the architecture and weights are
# reloaded from them.
@pytest.mark.parametrize('extension, compile_model', [('keras', True), ('h5', False)])
def test_dbitnet_save_and_load(tmp_path, extension, compile_model):
    model = _dbitnet()
    x = np.random.default_rng(0).integers(0, 2, (3, 64, 1)).astype(np.float32)
    path = str(tmp_path / f'dbitnet.{extension}')
    model.save(path)
    loaded = tf.keras.models.load_model(path, compile=compile_model)
    assert [type(layer).__name__ for layer in loaded.layers] == [type(layer).__name__ for layer in model.layers]
    np.testing.assert_allclose(loaded.predict(x, verbose=0), model.predict(x, verbose=0), rtol=1e-6)


def _synthetic_output_differences(biased):
    if biased:
        return np.full((SYNTHETIC_SAMPLES, SYNTHETIC_OUTPUT_BYTES), 0xFF, dtype=np.uint8)
    return np.array([[0x00] * SYNTHETIC_OUTPUT_BYTES, [0xFF] * SYNTHETIC_OUTPUT_BYTES] * (SYNTHETIC_SAMPLES // 2),
                    dtype=np.uint8)


def _synthetic_scores(biased_rounds_per_candidate, number_of_rounds, threshold):
    rounds = range(1, number_of_rounds + 1)
    c0 = {r: np.zeros((SYNTHETIC_SAMPLES, SYNTHETIC_OUTPUT_BYTES), dtype=np.uint8) for r in rounds}
    c1 = {r: np.concatenate([_synthetic_output_differences(r in biased_rounds)
                             for biased_rounds in biased_rounds_per_candidate]) for r in rounds}
    candidates = np.array(range(1, len(biased_rounds_per_candidate) + 1), dtype=object)
    inputs0 = [np.zeros((1, SYNTHETIC_SAMPLES), dtype=np.uint8)]
    return NeuralNetworkTests(None)._evaluate_multiple_differences([8], [True], lambda _: c1, candidates, inputs0,
                                                                   c0, threshold)


@pytest.mark.parametrize('biased_round', [1, 2, 3, 4])
def test_evaluate_multiple_differences_weights_each_round(biased_round):
    scores, highest_round = _synthetic_scores([{biased_round}], number_of_rounds=4, threshold=0)
    np.testing.assert_array_equal(scores, [0.5 * biased_round])
    assert highest_round == 4


def test_evaluate_multiple_differences_covers_the_terminal_rounds():
    scores, highest_round = _synthetic_scores([{1, 2, 3, 4}, {1, 2, 3}, {1, 2, 4}], number_of_rounds=4,
                                              threshold=0.05)
    np.testing.assert_array_equal(scores, [5.0, 3.0, 3.5])
    assert highest_round == 4


def test_evaluate_multiple_differences_stops_at_the_first_unbiased_round():
    scores, highest_round = _synthetic_scores([{1, 2, 4}, {1}], number_of_rounds=4, threshold=0.05)
    np.testing.assert_array_equal(scores, [1.5, 0.5])
    assert highest_round == 2


def test_evaluate_multiple_differences_without_biased_round():
    scores, highest_round = _synthetic_scores([set(), {2}], number_of_rounds=2, threshold=0.05)
    np.testing.assert_array_equal(scores, [0.0, 0.0])
    assert highest_round == 0


@pytest.mark.parametrize('cipher, expected', [
    (SpeckBlockCipher(number_of_rounds=1), {1: ('cipher_output', 0)}),
    (SpeckBlockCipher(number_of_rounds=4), {1: ('round_output', 0), 2: ('round_output', 1),
                                            3: ('round_output', 2), 4: ('cipher_output', 0)}),
    (SimonBlockCipher(number_of_rounds=2), {1: ('round_output', 0), 2: ('cipher_output', 0)}),
])
def test_scored_round_outputs(cipher, expected):
    assert NeuralNetworkTests(cipher)._scored_round_outputs() == expected


@pytest.mark.parametrize('number_of_rounds', [1, 2])
def test_find_good_input_difference_for_short_primitives(number_of_rounds):
    random.seed(0)
    np.random.seed(0)
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=number_of_rounds))
    diff, scores, highest_round = tester.find_good_input_difference_for_neural_distinguisher(
        [True, False], initial_population=4, number_of_generations=1, nb_samples=64)
    assert highest_round == number_of_rounds
    assert np.max(scores) > 0
    assert all(0 < d < 1 << 32 for d in diff)


@pytest.mark.parametrize('highest_round, round_start', [(0, 1), (2, 1), (5, 2)])
def test_run_autond_pipeline_starts_training_from_highest_round(highest_round, round_start):
    tester = NeuralNetworkTests(SpeckBlockCipher(number_of_rounds=5))
    search_result = (np.array([0x400000], dtype=object), np.array([1.0]), highest_round)
    with mock.patch.object(tester, 'find_good_input_difference_for_neural_distinguisher',
                           return_value=search_result), \
            mock.patch.object(tester, 'get_neural_network'), \
            mock.patch.object(tester, 'train_neural_distinguisher', return_value={round_start: 0.9}) as train:
        result = tester.run_autond_pipeline(optimizer_samples=4, optimizer_generations=1, training_samples=4,
                                            testing_samples=4, number_of_epochs=1)
    assert train.call_args.args[1] == round_start
    assert result['test_results']['round_start'] == round_start
