import importlib.util

import pytest

from claasp.analysis.neural import NeuralDataset, NeuralExperiment
from claasp.drivers.neural import (
    TensorFlowDistinguisherDriver,
    build_dbitnet,
    build_gohr_resnet,
)

pytestmark = pytest.mark.external


def _dataset(samples=64, width=16):
    labels = tuple(index % 2 for index in range(samples))
    features = tuple(
        tuple(label if bit % 2 == 0 else 1 - label for bit in range(width)) for label in labels
    )
    return NeuralDataset(
        features,
        labels,
        "xor_differential",
        3,
        tuple(f"x[{index}]" for index in range(width)),
    )


@pytest.mark.skipif(importlib.util.find_spec("tensorflow") is None, reason="TensorFlow absent")
def test_legacy_gohr_and_dbitnet_architectures_build_and_train():
    import tensorflow as tf

    gohr = build_gohr_resnet(16, word_size=4, depth=1, filters=4, dense_widths=(8, 4))
    dbitnet = build_dbitnet(16, filters=4, additional_filters=2, dense_widths=(8, 8, 4))
    assert gohr.name == "gohr_resnet"
    assert gohr.input_shape == (None, 16)
    assert dbitnet.name == "dbitnet"
    assert dbitnet.input_shape == (None, 16, 1)

    driver = TensorFlowDistinguisherDriver(word_size=4, depth=1, filters=4)
    result = driver.train(
        _dataset(),
        NeuralExperiment("gohr_resnet", epochs=1, batch_size=16, validation_fraction=0.25),
    )
    assert result.driver == "tensorflow-gohr_resnet"
    assert len(result.validation_accuracy) == 1
    assert driver.model is not None
    driver.reset()
    assert driver.model is None
    tf.keras.backend.clear_session()
