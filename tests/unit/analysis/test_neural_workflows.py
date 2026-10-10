from claasp.analysis.neural import NeuralExperiment, NeuralExperimentResult
from claasp.analysis.neural_workflows import (
    find_good_input_difference,
    run_autond,
    train_staged_neural_distinguisher,
)
from claasp.primitives import Speck


class SequenceDriver:
    def __init__(self, accuracies=(0.9, 0.5)):
        self.accuracies = iter(accuracies)
        self.datasets = []

    def train(self, dataset, experiment):
        self.datasets.append((dataset, experiment))
        return NeuralExperimentResult((next(self.accuracies),), "sequence", True)


def test_difference_search_is_seeded_ranked_and_covers_every_input():
    primitive = Speck(number_of_rounds=2)
    first = find_good_input_difference(
        primitive,
        active_inputs=("plaintext",),
        population=4,
        generations=1,
        samples=8,
        seed=7,
        initial_candidates=(1, 2, 4, 8),
    )
    second = primitive.analysis.find_good_neural_input_difference(
        active_inputs=("plaintext",),
        population=4,
        generations=1,
        samples=8,
        seed=7,
        initial_candidates=(1, 2, 4, 8),
    )

    assert first == second
    assert first.best.score >= first.candidates[0].score
    assert dict(first.best.input_differences)["key"] == 0
    assert 1 <= first.best.highest_round <= 2


def test_staged_training_stops_after_accuracy_loses_significance():
    primitive = Speck(number_of_rounds=3)
    driver = SequenceDriver()
    result = train_staged_neural_distinguisher(
        primitive,
        driver,
        {"plaintext": 0x0040_0000, "key": 0},
        starting_round=1,
        samples=32,
        significance_samples=10_000,
        experiment=NeuralExperiment("mlp", epochs=1, validation_fraction=0.25, seed=3),
    )

    assert tuple(item.round_number for item in result.rounds) == (1, 2)
    assert result.rounds[0].result.validation_accuracy == (0.9,)
    assert result.rounds[1].result.validation_accuracy == (0.5,)
    assert len(driver.datasets) == 2


def test_autond_executes_search_and_training_through_public_facade():
    primitive = Speck(number_of_rounds=2)
    driver = SequenceDriver((0.5,))
    experiment = NeuralExperiment("mlp", epochs=1)
    direct = run_autond(
        primitive,
        driver,
        experiment,
        active_inputs=("plaintext",),
        optimizer_population=2,
        optimizer_generations=0,
        optimizer_samples=4,
        training_samples=8,
        seed=5,
    )

    assert direct.difference_search.best.packed_difference > 0
    assert len(direct.training.rounds) == 1

    facade = primitive.analysis.run_autond(
        SequenceDriver((0.5,)),
        experiment,
        active_inputs=("plaintext",),
        optimizer_population=2,
        optimizer_generations=0,
        optimizer_samples=4,
        training_samples=8,
        seed=5,
    )
    assert facade.difference_search == direct.difference_search
