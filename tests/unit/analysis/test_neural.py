from dataclasses import FrozenInstanceError

import pytest

from claasp.analysis.neural import (
    NeuralDataset,
    NeuralExperiment,
    NeuralExperimentResult,
    black_box_dataset,
    xor_differential_dataset,
)
from claasp.primitives import Speck


def test_black_box_dataset_is_seeded_binary_and_preserves_legacy_shape():
    primitive = Speck(number_of_rounds=1)
    first = black_box_dataset(primitive, "plaintext", samples=12, seed=41)
    second = black_box_dataset(primitive, "plaintext", samples=12, seed=41)

    assert first == second
    assert first.kind == "black_box"
    assert first.sample_count == 12
    assert first.feature_width == 64  # legacy L || R shape for Speck32
    assert set(first.labels) == {0, 1}
    assert all(bit in (0, 1) for row in first.features for bit in row)


def test_differential_dataset_is_seeded_and_has_two_outputs():
    primitive = Speck(number_of_rounds=1)
    differences = {"plaintext": 0x0040_0000, "key": 0}
    dataset = xor_differential_dataset(primitive, differences, samples=16, seed=7)

    assert dataset == xor_differential_dataset(primitive, differences, samples=16, seed=7)
    assert dataset.kind == "xor_differential"
    assert dataset.feature_width == 64
    assert dataset.feature_names[0] == "output_0[0]"
    assert dataset.feature_names[-1] == "output_1[31]"


def test_dataset_generation_validates_contract_boundaries():
    primitive = Speck(number_of_rounds=1)
    with pytest.raises(ValueError, match="unknown primitive input"):
        black_box_dataset(primitive, "message", samples=2)
    with pytest.raises(ValueError, match="every primitive input"):
        xor_differential_dataset(primitive, {"plaintext": 1}, samples=2)
    with pytest.raises(ValueError, match="does not fit"):
        xor_differential_dataset(primitive, {"plaintext": 1 << 32, "key": 0}, samples=2)


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


def test_explicit_fixed_key_is_used_for_both_differential_classes(monkeypatch):
    primitive = Speck(number_of_rounds=1)
    calls = []
    evaluate = type(primitive).evaluate

    def capture(self, inputs):
        calls.append(dict(inputs))
        return evaluate(self, inputs)

    monkeypatch.setattr(type(primitive), "evaluate", capture)
    dataset = xor_differential_dataset(
        primitive,
        {"plaintext": 0x400000, "key": 0},
        samples=32,
        seed=9,
        fixed_inputs={"key": 17},
    )
    assert set(dataset.labels) == {0, 1}
    assert len(calls) == 64
    assert {inputs["key"] for inputs in calls} == {17}
    for index, label in enumerate(dataset.labels):
        if label:
            assert calls[2 * index]["plaintext"] ^ calls[2 * index + 1]["plaintext"] == 0x400000


@pytest.mark.parametrize("fixed", [{"missing": 0}, {"key": -1}, {"key": 1 << 64}, {"key": True}])
def test_fixed_inputs_reject_unknown_or_invalid_values(fixed):
    with pytest.raises((ValueError, TypeError)):
        black_box_dataset(Speck(number_of_rounds=1), "plaintext", samples=4, fixed_inputs=fixed)


def test_fixed_inputs_cannot_be_varied_or_have_nonzero_difference():
    primitive = Speck(number_of_rounds=1)
    with pytest.raises(ValueError, match="varied input"):
        black_box_dataset(primitive, "plaintext", samples=4, fixed_inputs={"plaintext": 0})
    with pytest.raises(ValueError, match="zero input difference"):
        xor_differential_dataset(
            primitive, {"plaintext": 1, "key": 1}, samples=4, fixed_inputs={"key": 0}
        )


def test_short_neural_api_records_dataset_and_training_settings_without_framework():
    class Driver:
        def train(self, dataset, experiment):
            self.dataset = dataset
            self.experiment = experiment
            return NeuralExperimentResult((0.6, 0.7), "test-driver", True)

    driver = Driver()
    result = Speck(number_of_rounds=2).analysis.neural_differential(
        "plaintext",
        0x400000,
        samples=24,
        epochs=2,
        seed=17,
        driver=driver,
        fixed_inputs={"key": 5},
    )
    from claasp.analysis import dataset_digest

    assert result.dataset_digests == (dataset_digest(driver.dataset),)
    assert result.experiment == driver.experiment
    assert result.fixed_inputs == (("key", 5),)
    assert result.rounds[0].round_number == 2
    assert result.dataset_seed == 17
    with pytest.raises(ValueError, match="nonzero"):
        Speck(number_of_rounds=1).analysis.neural_differential(driver=driver)
