"""Reproducible dataset splits and provenance for neural experiments."""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from random import Random

from claasp_next.analysis.neural import NeuralDataset, NeuralExperiment


@dataclass(frozen=True, slots=True)
class DatasetPartition:
    """Disjoint indices assigned to training, validation, and testing."""

    training: tuple[int, ...]
    validation: tuple[int, ...]
    testing: tuple[int, ...]

    def __post_init__(self) -> None:
        groups = self.training, self.validation, self.testing
        if any(index < 0 for group in groups for index in group):
            raise ValueError("partition indices must be non-negative")
        flattened = tuple(index for group in groups for index in group)
        if len(flattened) != len(set(flattened)):
            raise ValueError("partition indices must be disjoint")

    def select(self, dataset: NeuralDataset, part: str) -> NeuralDataset:
        """Return one partition while retaining dataset provenance."""

        try:
            indices = {
                "training": self.training,
                "validation": self.validation,
                "testing": self.testing,
            }[part]
        except KeyError as error:
            raise ValueError("part must be 'training', 'validation', or 'testing'") from error
        if any(index >= dataset.sample_count for index in indices):
            raise ValueError("partition contains an index outside the dataset")
        return NeuralDataset(
            tuple(dataset.features[index] for index in indices),
            tuple(dataset.labels[index] for index in indices),
            dataset.kind,
            dataset.seed,
            dataset.feature_names,
        )


def deterministic_partition(
    dataset: NeuralDataset,
    *,
    validation_fraction: float = 0.1,
    testing_fraction: float = 0.1,
    seed: int = 0,
    stratified: bool = True,
) -> DatasetPartition:
    """Partition a dataset reproducibly, optionally preserving label balance.

    Counts use floor rounding within each label stratum.  This mirrors the
    small-validation bias of common ML tools while defining it independently
    of any particular framework or version.
    """

    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")
    for name, fraction in (
        ("validation_fraction", validation_fraction),
        ("testing_fraction", testing_fraction),
    ):
        if not 0.0 <= fraction < 1.0:
            raise ValueError(f"{name} must be in the half-open interval [0, 1)")
    if validation_fraction + testing_fraction >= 1.0:
        raise ValueError("validation and testing fractions must sum to less than one")
    random = Random(seed)
    strata = (
        [[index for index, label in enumerate(dataset.labels) if label == value] for value in (0, 1)]
        if stratified
        else [list(range(dataset.sample_count))]
    )
    training: list[int] = []
    validation: list[int] = []
    testing: list[int] = []
    for indices in strata:
        random.shuffle(indices)
        validation_count = int(len(indices) * validation_fraction)
        testing_count = int(len(indices) * testing_fraction)
        validation.extend(indices[:validation_count])
        testing.extend(indices[validation_count : validation_count + testing_count])
        training.extend(indices[validation_count + testing_count :])
    # Shuffle each output independently so stratification does not group labels.
    random.shuffle(training)
    random.shuffle(validation)
    random.shuffle(testing)
    return DatasetPartition(tuple(training), tuple(validation), tuple(testing))


def dataset_digest(dataset: NeuralDataset) -> str:
    """Return a stable SHA-256 identity for exact features and labels."""

    digest = sha256()
    digest.update(dataset.kind.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(dataset.seed).encode("ascii"))
    for name in dataset.feature_names:
        digest.update(b"\0")
        digest.update(name.encode("utf-8"))
    for row, label in zip(dataset.features, dataset.labels):
        digest.update(bytes(row))
        digest.update(bytes((label,)))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class NeuralRunProvenance:
    """Information required to identify and reproduce one training run."""

    primitive: str
    realization: str
    dataset_digest: str
    dataset_kind: str
    dataset_seed: int
    partition_seed: int
    driver: str
    driver_version: str
    options: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(
        cls,
        dataset: NeuralDataset,
        *,
        primitive: str,
        realization: str = "default",
        partition_seed: int,
        driver: str,
        driver_version: str,
        options: Mapping[str, object] | None = None,
    ) -> "NeuralRunProvenance":
        """Normalize driver options into a stable, ordered representation."""

        fields = (primitive, realization, driver, driver_version)
        if any(not value for value in fields):
            raise ValueError("provenance names and versions must not be empty")
        if not isinstance(partition_seed, int) or isinstance(partition_seed, bool):
            raise TypeError("partition_seed must be an integer")
        if any(not isinstance(value, (str, int, float, bool, type(None)))
               for value in (options or {}).values()):
            raise TypeError("provenance option values must be scalar")
        normalized = tuple(sorted((str(key), repr(value)) for key, value in (options or {}).items()))
        return cls(
            primitive,
            realization,
            dataset_digest(dataset),
            dataset.kind,
            dataset.seed,
            partition_seed,
            driver,
            driver_version,
            normalized,
        )


@dataclass(frozen=True, slots=True)
class NeuralRun:
    """A complete portable request: experiment, exact split, and provenance."""

    experiment: NeuralExperiment
    partition: DatasetPartition
    provenance: NeuralRunProvenance

    def validate_for(self, dataset: NeuralDataset) -> None:
        """Reject stale provenance or incomplete/foreign partitions."""

        if self.provenance.dataset_digest != dataset_digest(dataset):
            raise ValueError("run provenance does not describe this dataset")
        indices = self.partition.training + self.partition.validation + self.partition.testing
        if set(indices) != set(range(dataset.sample_count)):
            raise ValueError("partition must cover every dataset sample exactly once")
