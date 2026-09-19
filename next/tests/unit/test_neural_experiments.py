import pytest

from claasp_next.analysis.neural import NeuralDataset, NeuralExperiment
from claasp_next.analysis.neural_experiments import (
    DatasetPartition,
    NeuralRun,
    NeuralRunProvenance,
    dataset_digest,
    deterministic_partition,
)


def _dataset() -> NeuralDataset:
    features = tuple((index >> 1 & 1, index & 1) for index in range(20))
    labels = tuple(index % 2 for index in range(20))
    return NeuralDataset(features, labels, "xor_differential", 17, ("x0", "x1"))


def test_partition_is_deterministic_disjoint_complete_and_stratified():
    dataset = _dataset()
    partition = deterministic_partition(
        dataset, validation_fraction=0.2, testing_fraction=0.2, seed=91
    )

    assert partition == deterministic_partition(
        dataset, validation_fraction=0.2, testing_fraction=0.2, seed=91
    )
    all_indices = partition.training + partition.validation + partition.testing
    assert len(partition.training) == 12
    assert len(partition.validation) == 4
    assert len(partition.testing) == 4
    assert set(all_indices) == set(range(20))
    assert sum(dataset.labels[index] for index in partition.validation) == 2
    assert sum(dataset.labels[index] for index in partition.testing) == 2


def test_partition_select_returns_framework_neutral_subdataset():
    dataset = _dataset()
    partition = deterministic_partition(dataset, validation_fraction=0.2, seed=3)
    validation = partition.select(dataset, "validation")

    assert validation.sample_count == 4
    assert validation.labels == tuple(dataset.labels[index] for index in partition.validation)
    assert validation.seed == dataset.seed
    with pytest.raises(ValueError, match="part must be"):
        partition.select(dataset, "holdout")


def test_digest_covers_data_labels_schema_kind_and_seed():
    dataset = _dataset()
    assert dataset_digest(dataset) == dataset_digest(dataset)
    changed_seed = NeuralDataset(
        dataset.features, dataset.labels, dataset.kind, 18, dataset.feature_names
    )
    changed_label = NeuralDataset(
        dataset.features, (1,) + dataset.labels[1:], dataset.kind, 17, dataset.feature_names
    )
    assert dataset_digest(dataset) != dataset_digest(changed_seed)
    assert dataset_digest(dataset) != dataset_digest(changed_label)


def test_run_provenance_normalizes_options_and_validates_dataset():
    dataset = _dataset()
    partition = deterministic_partition(dataset, validation_fraction=0.2, seed=5)
    provenance = NeuralRunProvenance.create(
        dataset,
        primitive="speck",
        realization="word",
        partition_seed=5,
        driver="pytorch",
        driver_version="2.8",
        options={"device": "cpu", "threads": 1},
    )
    run = NeuralRun(NeuralExperiment("gohr_resnet"), partition, provenance)

    run.validate_for(dataset)
    assert provenance.options == (("device", "'cpu'"), ("threads", "1"))
    with pytest.raises(ValueError, match="does not describe"):
        run.validate_for(
            NeuralDataset(dataset.features, dataset.labels, dataset.kind, 99, dataset.feature_names)
        )


def test_split_contract_rejects_overlap_bad_fractions_and_incomplete_runs():
    dataset = _dataset()
    with pytest.raises(ValueError, match="disjoint"):
        DatasetPartition((0, 1), (1,), ())
    with pytest.raises(ValueError, match="sum to less"):
        deterministic_partition(dataset, validation_fraction=0.5, testing_fraction=0.5)
    run = NeuralRun(
        NeuralExperiment("mlp"),
        DatasetPartition((0,), (), ()),
        NeuralRunProvenance.create(
            dataset,
            primitive="toy",
            partition_seed=0,
            driver="test",
            driver_version="1",
        ),
    )
    with pytest.raises(ValueError, match="cover every"):
        run.validate_for(dataset)
    with pytest.raises(TypeError, match="scalar"):
        NeuralRunProvenance.create(
            dataset,
            primitive="toy",
            partition_seed=0,
            driver="test",
            driver_version="1",
            options={"layers": [32, 32]},
        )
