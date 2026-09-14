from dataclasses import FrozenInstanceError

import pytest

from claasp_next.analysis.neural import (
    NeuralDataset,
    NeuralExperiment,
    NeuralExperimentResult,
    black_box_dataset,
    xor_differential_dataset,
)
from claasp_next.ciphers import SpeckBlockCipher


def test_black_box_dataset_is_seeded_binary_and_preserves_legacy_shape():
    primitive = SpeckBlockCipher(number_of_rounds=1)
    first = black_box_dataset(primitive, "plaintext", samples=12, seed=41)
    second = black_box_dataset(primitive, "plaintext", samples=12, seed=41)

    assert first == second
    assert first.kind == "black_box"
    assert first.sample_count == 12
    assert first.feature_width == 64  # legacy L || R shape for Speck32
    assert set(first.labels) == {0, 1}
    assert all(bit in (0, 1) for row in first.features for bit in row)


def test_differential_dataset_is_seeded_and_has_two_outputs():
    primitive = SpeckBlockCipher(number_of_rounds=1)
    differences = {"plaintext": 0x0040_0000, "key": 0}
    dataset = xor_differential_dataset(primitive, differences, samples=16, seed=7)

    assert dataset == xor_differential_dataset(
        primitive, differences, samples=16, seed=7
    )
    assert dataset.kind == "xor_differential"
    assert dataset.feature_width == 64
    assert dataset.feature_names[0] == "output_0[0]"
    assert dataset.feature_names[-1] == "output_1[31]"


def test_dataset_generation_validates_contract_boundaries():
    primitive = SpeckBlockCipher(number_of_rounds=1)
    with pytest.raises(ValueError, match="unknown primitive input"):
        black_box_dataset(primitive, "message", samples=2)
    with pytest.raises(ValueError, match="every primitive input"):
        xor_differential_dataset(primitive, {"plaintext": 1}, samples=2)
    with pytest.raises(ValueError, match="does not fit"):
        xor_differential_dataset(
            primitive, {"plaintext": 1 << 32, "key": 0}, samples=2
        )


def test_neural_experiment_and_result_are_framework_neutral_value_objects():
    request = NeuralExperiment("gohr_resnet", epochs=3, batch_size=32, seed=9)
    result = NeuralExperimentResult((0.5, 0.625), "test-driver", True)

    assert request.architecture == "gohr_resnet"
    assert result.validation_accuracy[-1] == 0.625
    with pytest.raises(FrozenInstanceError):
        request.epochs = 4
    with pytest.raises(ValueError, match="between zero and one"):
        NeuralExperimentResult((1.1,), "test-driver", True)


def test_neural_dataset_rejects_ragged_or_non_binary_data():
    with pytest.raises(ValueError, match="same width"):
        NeuralDataset(((0,), (0, 1)), (0, 1), "black_box", 0, ("x",))
    with pytest.raises(ValueError, match="binary"):
        NeuralDataset(((2,),), (1,), "black_box", 0, ("x",))
    with pytest.raises(ValueError, match="feature_names"):
        NeuralDataset(((0, 1),), (1,), "black_box", 0, ("x",))
