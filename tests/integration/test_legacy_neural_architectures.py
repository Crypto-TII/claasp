"""Numerical architecture parity with the original legacy network builders."""

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.external


@pytest.mark.skipif(importlib.util.find_spec("tensorflow") is None, reason="TensorFlow absent")
@pytest.mark.parametrize("architecture", ["gohr_resnet", "dbitnet"])
def test_legacy_and_v5_networks_have_identical_weight_layouts_and_forward_values(architecture):
    import numpy as np
    import tensorflow as tf

    from claasp.drivers.neural import build_dbitnet, build_gohr_resnet

    fixture = Path(__file__).parents[1] / "fixtures/legacy_parity/neural_builders.py"
    spec = importlib.util.spec_from_file_location("legacy_neural_builders", fixture)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = module.LegacyNeuralBuilders()
    tf.keras.utils.set_random_seed(9)
    if architecture == "gohr_resnet":
        legacy = original._make_resnet(input_size=64, word_size=16, depth=1)
        current = build_gohr_resnet(64, word_size=16, depth=1)
        features = np.random.default_rng(9).integers(0, 2, size=(8, 64)).astype(np.float32)
    else:
        legacy = original._make_dbitnet(input_size=64)
        current = build_dbitnet(64)
        features = np.random.default_rng(9).integers(0, 2, size=(8, 64, 1)).astype(np.float32)
    assert legacy.count_params() == current.count_params()
    assert [tuple(weight.shape) for weight in legacy.weights] == [
        tuple(weight.shape) for weight in current.weights
    ]
    for cls in (tf.keras.layers.Conv1D, tf.keras.layers.Dense):
        old_layers = [layer for layer in legacy.layers if isinstance(layer, cls)]
        new_layers = [layer for layer in current.layers if isinstance(layer, cls)]
        assert len(old_layers) == len(new_layers)
        for old, new in zip(old_layers, new_layers):
            for field in (
                "activation",
                "kernel_size",
                "dilation_rate",
                "padding",
                "filters",
                "units",
            ):
                assert old.get_config().get(field) == new.get_config().get(field)
    current.set_weights(legacy.get_weights())
    np.testing.assert_allclose(
        legacy(features, training=False).numpy(),
        current(features, training=False).numpy(),
        rtol=1e-6,
        atol=1e-6,
    )
    tf.keras.backend.clear_session()
