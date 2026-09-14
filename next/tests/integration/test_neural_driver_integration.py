import importlib.util

import pytest

from claasp_next.analysis.neural import NeuralExperiment, xor_differential_dataset
from claasp_next.ciphers import SpeckBlockCipher
from claasp_next.drivers.neural import SklearnMLPDriver


pytestmark = pytest.mark.external


@pytest.mark.skipif(
    importlib.util.find_spec("sklearn") is None,
    reason="scikit-learn is not installed (pip install 'claasp-next[ml]')",
)
def test_sklearn_driver_trains_a_bounded_reduced_round_differential_distinguisher():
    """End-to-end: dataset generation, a real ML framework, and a real bias.

    Two-round Speck32/64 with the classic 0x00400000 input difference is a
    small, well-known differential distinguisher target (see
    ``claasp/cipher_modules/neural_network_tests.py`` and Gohr's original
    experiments); it trains to high accuracy in a handful of epochs on a few
    thousand samples, which keeps this bounded well under the project's
    ten-second routine-integration budget while still exercising a real,
    non-synthetic cryptographic bias rather than a trivially separable toy
    dataset (that lives in the fast unit-level driver test instead).
    """

    primitive = SpeckBlockCipher(number_of_rounds=2)
    dataset = xor_differential_dataset(
        primitive, {"plaintext": 0x0040_0000, "key": 0}, samples=3000, seed=11
    )
    experiment = NeuralExperiment("mlp", epochs=15, batch_size=64, seed=2)

    result = SklearnMLPDriver(hidden_layer_sizes=(32, 32)).train(dataset, experiment)

    assert result.driver == "sklearn-mlp"
    assert len(result.validation_accuracy) == experiment.epochs
    # Tolerance/threshold-based experimental evidence, not an exact
    # cross-platform accuracy fixture (docs/architecture/v5-plan.md M10.13).
    assert result.validation_accuracy[-1] > 0.8
