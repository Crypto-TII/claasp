"""Optional scikit-learn training driver for neural distinguisher experiments.

CLAASP v5 keeps machine-learning frameworks optional and out of ordinary
imports (see ``docs/architecture/v5-plan.md`` M10.13). Legacy CLAASP
(``claasp/cipher_modules/neural_network_tests.py``) trained its distinguishers
with TensorFlow/Keras -- ``docker/Dockerfile`` pins ``tensorflow==2.13.0`` --
which is a multi-hundred-megabyte, GPU-toolchain-aware dependency. For v5's
bounded CI job and fast unit tests this module deliberately chooses
scikit-learn's ``MLPClassifier`` instead: it installs in seconds with no
native/GPU toolchain, trains a small multilayer perceptron in well under a
second on the tiny synthetic and reduced-round datasets CLAASP's dataset
contracts produce, and is sufficient to exercise the framework-neutral
:class:`~claasp_next.analysis.neural.NeuralTrainingDriver` protocol end to
end. TensorFlow/Keras, PyTorch, or any other framework remains a valid,
swappable alternative driver behind the same protocol; nothing in
``claasp_next``'s core, nor this module at import time, requires scikit-learn
-- only calling :meth:`SklearnMLPDriver.train` does.
"""

from __future__ import annotations

from claasp_next.analysis.neural import NeuralDataset, NeuralExperiment, NeuralExperimentResult
from claasp_next.analysis.neural_experiments import deterministic_partition


class SklearnMLPDriver:
    """``NeuralTrainingDriver`` backed by ``sklearn.neural_network.MLPClassifier``.

    The scikit-learn import happens inside :meth:`train`, never at module
    import time, so constructing or merely holding a reference to this class
    does not require the optional ``ml`` extra (``pip install
    'claasp-next[ml]'``).
    """

    def __init__(self, hidden_layer_sizes: tuple[int, ...] = (32, 32)) -> None:
        if not hidden_layer_sizes or any(size <= 0 for size in hidden_layer_sizes):
            raise ValueError("hidden_layer_sizes must contain positive integers")
        self.hidden_layer_sizes = tuple(hidden_layer_sizes)

    def train(self, dataset: NeuralDataset, experiment: NeuralExperiment) -> NeuralExperimentResult:
        """Train a small MLP and report per-epoch validation accuracy.

        ``experiment.seed`` seeds scikit-learn's ``random_state``, and the
        deterministic, seeded :func:`~claasp_next.analysis.neural_experiments.deterministic_partition`
        supplies the train/validation split, so repeated calls with the same
        dataset and experiment are reproducible on a fixed scikit-learn
        version and single-threaded execution. Report
        ``validation_accuracy`` as tolerance-based experimental evidence
        only -- never assert an exact value against it.
        """

        try:
            import numpy as np
            from sklearn.neural_network import MLPClassifier
        except ImportError as error:
            raise ImportError(
                "SklearnMLPDriver requires the optional 'ml' extra: pip install 'claasp-next[ml]'"
            ) from error

        if not isinstance(dataset, NeuralDataset):
            raise TypeError("dataset must be a NeuralDataset")
        if not isinstance(experiment, NeuralExperiment):
            raise TypeError("experiment must be a NeuralExperiment")

        partition = deterministic_partition(
            dataset,
            validation_fraction=experiment.validation_fraction,
            testing_fraction=0.0,
            seed=experiment.seed,
        )
        training = partition.select(dataset, "training")
        validation = partition.select(dataset, "validation")
        if not training.features or not validation.features:
            raise ValueError("dataset is too small to produce a non-empty train/validation split")

        features_train = np.array(training.features, dtype=np.float64)
        labels_train = np.array(training.labels, dtype=np.int64)
        features_validation = np.array(validation.features, dtype=np.float64)
        labels_validation = np.array(validation.labels, dtype=np.int64)

        classifier = MLPClassifier(
            hidden_layer_sizes=self.hidden_layer_sizes,
            batch_size=min(experiment.batch_size, len(features_train)),
            random_state=experiment.seed,
        )
        classes = np.array([0, 1])
        accuracies: list[float] = []
        for _ in range(experiment.epochs):
            classifier.partial_fit(features_train, labels_train, classes=classes)
            accuracies.append(float(classifier.score(features_validation, labels_validation)))

        return NeuralExperimentResult(
            validation_accuracy=tuple(accuracies),
            driver="sklearn-mlp",
            deterministic=True,
        )
