"""Optional TensorFlow implementations of the legacy Gohr and DBitNet models."""

from __future__ import annotations

from typing import Any

from claasp.analysis.neural import NeuralDataset, NeuralExperiment, NeuralExperimentResult
from claasp.analysis.neural_experiments import deterministic_partition


def build_gohr_resnet(
    input_size: int,
    *,
    word_size: int,
    depth: int = 1,
    filters: int = 32,
    dense_widths: tuple[int, int] = (64, 64),
):
    """Build the residual convolutional distinguisher used by Gohr.

    EXAMPLES::

        >>> callable(build_gohr_resnet)
        True
    """

    tf = _tensorflow()
    _positive("input_size", input_size)
    _positive("word_size", word_size)
    _positive("depth", depth)
    _positive("filters", filters)
    if input_size % word_size:
        raise ValueError("input_size must be divisible by word_size")
    regularizer = tf.keras.regularizers.l2(1e-5)
    inputs = tf.keras.layers.Input(shape=(input_size,))
    value = tf.keras.layers.Reshape((input_size // word_size, word_size))(inputs)
    value = tf.keras.layers.Permute((2, 1))(value)
    value = tf.keras.layers.Conv1D(filters, 1, padding="same", kernel_regularizer=regularizer)(
        value
    )
    value = tf.keras.layers.BatchNormalization()(value)
    shortcut = tf.keras.layers.Activation("relu")(value)
    for _ in range(depth):
        value = tf.keras.layers.Conv1D(filters, 3, padding="same", kernel_regularizer=regularizer)(
            shortcut
        )
        value = tf.keras.layers.BatchNormalization()(value)
        value = tf.keras.layers.Activation("relu")(value)
        value = tf.keras.layers.Conv1D(filters, 3, padding="same", kernel_regularizer=regularizer)(
            value
        )
        value = tf.keras.layers.BatchNormalization()(value)
        value = tf.keras.layers.Activation("relu")(value)
        shortcut = tf.keras.layers.Add()((shortcut, value))
    value = tf.keras.layers.Flatten()(shortcut)
    for width in dense_widths:
        _positive("dense width", width)
        value = tf.keras.layers.Dense(width, kernel_regularizer=regularizer)(value)
        value = tf.keras.layers.BatchNormalization()(value)
        value = tf.keras.layers.Activation("relu")(value)
    output = tf.keras.layers.Dense(1, activation="sigmoid", kernel_regularizer=regularizer)(value)
    return tf.keras.Model(inputs=inputs, outputs=output, name="gohr_resnet")


def build_dbitnet(
    input_size: int,
    *,
    filters: int = 32,
    additional_filters: int = 16,
    dense_widths: tuple[int, int, int] = (256, 256, 64),
):
    """Build the dilated-bit neural distinguisher used by AutoND.

    EXAMPLES::

        >>> callable(build_dbitnet)
        True
    """

    tf = _tensorflow()
    _positive("input_size", input_size)
    _positive("filters", filters)
    _positive("additional_filters", additional_filters)
    inputs = tf.keras.layers.Input(shape=(input_size, 1))
    value = (inputs - 0.5) / 0.5
    current_filters = filters
    size = input_size
    while size >= 8:
        dilation = size // 2 - 1
        value = tf.keras.layers.Conv1D(
            current_filters,
            2,
            padding="valid",
            dilation_rate=dilation,
            activation="relu",
        )(value)
        value = tf.keras.layers.BatchNormalization()(value)
        skip = value
        value = tf.keras.layers.Conv1D(current_filters, 2, padding="causal", activation="relu")(
            value
        )
        value = tf.keras.layers.Add()((value, skip))
        value = tf.keras.layers.BatchNormalization()(value)
        current_filters += additional_filters
        size //= 2
    value = tf.keras.layers.Flatten()(value)
    regularizer = tf.keras.regularizers.l2(1e-5)
    for width in dense_widths:
        _positive("dense width", width)
        value = tf.keras.layers.Dense(width, kernel_regularizer=regularizer)(value)
        value = tf.keras.layers.BatchNormalization()(value)
        value = tf.keras.layers.Activation("relu")(value)
    output = tf.keras.layers.Dense(1, activation="sigmoid", kernel_regularizer=regularizer)(value)
    return tf.keras.Model(inputs=inputs, outputs=output, name="dbitnet")


class TensorFlowDistinguisherDriver:
    """Train true Gohr ResNet or DBitNet architectures behind an optional driver.

    EXAMPLES::

        >>> TensorFlowDistinguisherDriver().model is None
        True
    """

    def __init__(
        self,
        *,
        word_size: int | None = None,
        depth: int = 1,
        filters: int = 32,
        reuse_model: bool = True,
    ) -> None:
        self.word_size = word_size
        self.depth = depth
        self.filters = filters
        self.reuse_model = reuse_model
        self._model: Any | None = None
        self._model_key: tuple[str, int] | None = None

    @property
    def model(self):
        """Return the most recently trained Keras model, if any."""

        return self._model

    def reset(self) -> None:
        """Discard retained weights before an independent experiment.

        EXAMPLES::

            >>> driver = TensorFlowDistinguisherDriver()
            >>> driver.reset()
            >>> driver.model is None
            True
        """

        self._model = None
        self._model_key = None

    def train(self, dataset: NeuralDataset, experiment: NeuralExperiment) -> NeuralExperimentResult:
        """Train the selected legacy architecture and return validation accuracy per epoch.

        EXAMPLES::

            >>> callable(TensorFlowDistinguisherDriver.train)
            True
        """

        tf = _tensorflow()
        try:
            import numpy as np
        except ImportError as error:  # pragma: no cover - TensorFlow itself requires NumPy
            raise ImportError("TensorFlowDistinguisherDriver requires NumPy") from error
        if not isinstance(dataset, NeuralDataset):
            raise TypeError("dataset must be a NeuralDataset")
        if not isinstance(experiment, NeuralExperiment):
            raise TypeError("experiment must be a NeuralExperiment")
        if experiment.architecture not in {"gohr_resnet", "dbitnet"}:
            raise ValueError("TensorFlow driver architecture must be 'gohr_resnet' or 'dbitnet'")

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

        tf.keras.utils.set_random_seed(experiment.seed)
        key = (experiment.architecture, dataset.feature_width)
        if not self.reuse_model or self._model is None or self._model_key != key:
            if experiment.architecture == "gohr_resnet":
                word_size = self.word_size or dataset.feature_width // 4
                self._model = build_gohr_resnet(
                    dataset.feature_width,
                    word_size=word_size,
                    depth=self.depth,
                    filters=self.filters,
                )
            else:
                self._model = build_dbitnet(dataset.feature_width, filters=self.filters)
            self._model.compile(
                optimizer=tf.keras.optimizers.Adam(amsgrad=True),
                loss="mse",
                metrics=["accuracy"],
            )
            self._model_key = key

        train_x = np.asarray(training.features, dtype=np.float32)
        validation_x = np.asarray(validation.features, dtype=np.float32)
        if experiment.architecture == "dbitnet":
            train_x = train_x[..., np.newaxis]
            validation_x = validation_x[..., np.newaxis]
        history = self._model.fit(
            train_x,
            np.asarray(training.labels, dtype=np.float32),
            validation_data=(validation_x, np.asarray(validation.labels, dtype=np.float32)),
            epochs=experiment.epochs,
            batch_size=min(experiment.batch_size, len(training.features)),
            shuffle=True,
            verbose=0,
        )
        accuracies = history.history.get("val_accuracy") or history.history.get("val_acc")
        if accuracies is None:
            raise RuntimeError("TensorFlow did not report validation accuracy")
        return NeuralExperimentResult(
            tuple(float(value) for value in accuracies),
            f"tensorflow-{experiment.architecture}",
            True,
        )


def _tensorflow():
    try:
        import tensorflow as tf
    except ImportError as error:
        raise ImportError(
            "TensorFlowDistinguisherDriver requires the optional 'ml-tensorflow' extra: "
            "pip install 'claasp[ml-tensorflow]'"
        ) from error
    return tf


def _positive(name, value):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
