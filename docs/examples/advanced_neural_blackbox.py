"""Reproducible advanced neural experiment."""

import numpy as np

from claasp.analysis import (
    NeuralExperiment,
    black_box_dataset,
    dataset_digest,
    deterministic_partition,
)
from claasp.drivers.neural import SklearnMLPDriver
from claasp.primitives import Speck


def run_example():
    primitive = Speck(number_of_rounds=1)
    dataset = black_box_dataset(
        primitive, "plaintext", samples=3000, seed=9, fixed_inputs={"key": 0}
    )
    partition = deterministic_partition(
        dataset, validation_fraction=0, testing_fraction=0.2, seed=19
    )
    development = partition.select(dataset, "training")
    testing = partition.select(dataset, "testing")
    driver = SklearnMLPDriver(hidden_layer_sizes=(32, 32))
    experiment = NeuralExperiment("mlp", epochs=15, batch_size=64, seed=9)
    result = driver.train(development, experiment)
    test_accuracy = driver.model.score(np.asarray(testing.features), np.asarray(testing.labels))
    return result, test_accuracy, dataset_digest(dataset)


if __name__ == "__main__":
    print(run_example())
