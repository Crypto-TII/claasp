import importlib.util
from random import Random

import pytest

from claasp.analysis.neural import NeuralDataset, NeuralExperiment
from claasp.drivers.neural import SklearnMLPDriver


def _separable_dataset(samples: int, seed: int) -> NeuralDataset:
    """A trivially linearly separable dataset: two features echo the label.

    Kept tiny and cleanly separable on purpose -- this unit test exercises
    the ``NeuralTrainingDriver`` contract end to end, not the ML framework's
    generalization behavior on a hard task, so it stays small and fast to
    train to a high, but never exact, accuracy threshold.
    """

    random = Random(seed)
    features: list[tuple[int, ...]] = []
    labels: list[int] = []
    for _ in range(samples):
        label = random.getrandbits(1)
        row = (label, label, 1 - label, 1 - label)
        features.append(row)
        labels.append(label)
    return NeuralDataset(
        tuple(features), tuple(labels), "black_box", seed, ("f0", "f1", "f2", "f3")
    )


def test_sklearn_mlp_driver_rejects_invalid_construction():
    with pytest.raises(ValueError, match="positive integers"):
        SklearnMLPDriver(hidden_layer_sizes=())
    with pytest.raises(ValueError, match="positive integers"):
        SklearnMLPDriver(hidden_layer_sizes=(8, 0))


# scikit-learn is an optional dependency behind the 'ml' extra
# (`pip install 'claasp[ml]'`); this test is skipped, not failed, when
# it is absent, mirroring how the msolve/Singular driver unit tests are
# gated on their optional external executables.
#
# NOTE on the "unit tests finish below one second" policy: importing NumPy
# and scikit-learn's MLPClassifier alone costs several hundred milliseconds
# to roughly a second even with a warm interpreter cache, before any
# training happens. That cost is inherent to choosing a real ML framework
# (see claasp/drivers/neural/sklearn_driver.py's docstring for why
# scikit-learn was chosen over TensorFlow/Keras specifically to keep this
# overhead as small as it can be for an ML dependency). This test keeps the
# dataset and epoch count minimal so only the unavoidable import/init cost,
# not the training itself, dominates its running time.
@pytest.mark.skipif(
    importlib.util.find_spec("sklearn") is None, reason="scikit-learn is not installed"
)
def test_sklearn_mlp_driver_trains_a_trivially_separable_distinguisher():
    dataset = _separable_dataset(samples=200, seed=1)
    experiment = NeuralExperiment("mlp", epochs=25, batch_size=32, seed=3)

    result = SklearnMLPDriver(hidden_layer_sizes=(8,)).train(dataset, experiment)

    assert result.driver == "sklearn-mlp"
    assert result.deterministic is True
    assert len(result.validation_accuracy) == experiment.epochs
    # Tolerance/threshold-based experimental evidence only -- never an exact
    # accuracy value (docs/architecture/v5-plan.md M10.13).
    assert result.validation_accuracy[-1] > 0.9


@pytest.mark.skipif(
    importlib.util.find_spec("sklearn") is None, reason="scikit-learn is not installed"
)
def test_sklearn_mlp_driver_is_reproducible_for_a_fixed_seed():
    dataset = _separable_dataset(samples=64, seed=5)
    experiment = NeuralExperiment("mlp", epochs=3, batch_size=16, seed=7)

    first = SklearnMLPDriver(hidden_layer_sizes=(8,)).train(dataset, experiment)
    second = SklearnMLPDriver(hidden_layer_sizes=(8,)).train(dataset, experiment)

    assert first.validation_accuracy == second.validation_accuracy
