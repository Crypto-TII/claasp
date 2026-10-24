"""Reproducible advanced neural experiment."""

from claasp.analysis import NeuralExperiment, xor_differential_component_dataset
from claasp.drivers.neural import SklearnMLPDriver
from claasp.primitives import Speck


def run_example():
    primitive = Speck(number_of_rounds=2)
    result = primitive.analysis.neural_differential(
        "plaintext",
        0x400000,
        samples=3000,
        epochs=15,
        seed=9,
        fixed_inputs={"key": 0},
    )
    right_word = primitive.graph.round_outputs[0][1].source_id
    projected = xor_differential_component_dataset(
        primitive,
        {"plaintext": 0x400000, "key": 0},
        right_word,
        samples=1000,
        seed=9,
    )
    projected_result = SklearnMLPDriver().train(
        projected, NeuralExperiment("mlp", epochs=5, seed=9)
    )
    return result, projected_result


if __name__ == "__main__":
    print(run_example())
