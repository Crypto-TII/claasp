"""Framework-independent contracts for neural distinguisher experiments.

This module deliberately generates ordinary Python data.  NumPy tensors and
framework-specific models belong in optional drivers, not in CLAASP's core.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from random import Random
from typing import Protocol

from claasp_next.graph import Cipher


def _positive_integer(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _bits(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> shift) & 1 for shift in range(width - 1, -1, -1))


def _widths(primitive: Cipher) -> dict[str, int]:
    widths = {name: port.value_type.encoded_bit_size for name, port in primitive.inputs.items()}
    if any(width is None for width in widths.values()):
        raise ValueError("neural datasets require canonically bit-encoded inputs")
    return {name: int(width) for name, width in widths.items()}


def _output_width(primitive: Cipher) -> int:
    if primitive.output is None:
        raise ValueError("the primitive must declare an output")
    width = primitive.output.value_type.encoded_bit_size
    if width is None:
        raise ValueError("neural datasets require a canonically bit-encoded output")
    return width


@dataclass(frozen=True, slots=True)
class NeuralDataset:
    """Binary features and labels with reproducibility metadata."""

    features: tuple[tuple[int, ...], ...]
    labels: tuple[int, ...]
    kind: str
    seed: int
    feature_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.kind not in {"black_box", "xor_differential"}:
            raise ValueError("unsupported neural dataset kind")
        if len(self.features) != len(self.labels):
            raise ValueError("features and labels must contain the same number of samples")
        widths = {len(row) for row in self.features}
        if len(widths) > 1:
            raise ValueError("all feature rows must have the same width")
        if self.features and len(self.feature_names) != len(self.features[0]):
            raise ValueError("feature_names must describe every feature column")
        if any(bit not in (0, 1) for row in self.features for bit in row):
            raise ValueError("features must be binary")
        if any(label not in (0, 1) for label in self.labels):
            raise ValueError("labels must be binary")
        if not isinstance(self.seed, int) or isinstance(self.seed, bool):
            raise TypeError("seed must be an integer")

    @property
    def sample_count(self) -> int:
        return len(self.labels)

    @property
    def feature_width(self) -> int:
        return len(self.features[0]) if self.features else len(self.feature_names)


@dataclass(frozen=True, slots=True)
class NeuralExperiment:
    """Portable training request consumed by an optional ML driver."""

    architecture: str
    epochs: int = 10
    batch_size: int = 64
    validation_fraction: float = 0.1
    seed: int = 0

    def __post_init__(self) -> None:
        if not self.architecture:
            raise ValueError("architecture must not be empty")
        _positive_integer("epochs", self.epochs)
        _positive_integer("batch_size", self.batch_size)
        if not 0.0 < self.validation_fraction < 1.0:
            raise ValueError("validation_fraction must be between zero and one")


@dataclass(frozen=True, slots=True)
class NeuralExperimentResult:
    """Framework-neutral summary returned by neural training drivers."""

    validation_accuracy: tuple[float, ...]
    driver: str
    deterministic: bool

    def __post_init__(self) -> None:
        if not self.driver:
            raise ValueError("driver must not be empty")
        if any(not 0.0 <= accuracy <= 1.0 for accuracy in self.validation_accuracy):
            raise ValueError("validation accuracies must be between zero and one")


class NeuralTrainingDriver(Protocol):
    """Structural interface implemented by optional ML integrations."""

    def train(
        self, dataset: NeuralDataset, experiment: NeuralExperiment
    ) -> NeuralExperimentResult: ...


def black_box_dataset(
    primitive: Cipher,
    varied_input: str,
    *,
    samples: int,
    seed: int = 0,
) -> NeuralDataset:
    """Generate the legacy ``L || real-or-random-output`` experiment.

    Other primitive inputs are fixed for the whole dataset, matching the
    black-box experiment in CLAASP 4.  Bit order is most-significant first.
    """

    _positive_integer("samples", samples)
    widths = _widths(primitive)
    if varied_input not in widths:
        raise ValueError(f"unknown primitive input {varied_input!r}")
    output_width = _output_width(primitive)
    random = Random(seed)
    fixed = {name: random.getrandbits(width) for name, width in widths.items()}
    rows: list[tuple[int, ...]] = []
    labels: list[int] = []
    for _ in range(samples):
        label = random.getrandbits(1)
        varied_value = random.getrandbits(widths[varied_input])
        inputs = dict(fixed)
        inputs[varied_input] = varied_value
        output = primitive.evaluate(inputs) if label else random.getrandbits(output_width)
        if not isinstance(output, int):
            raise TypeError("neural datasets currently require an integer-encoded output")
        rows.append(_bits(varied_value, widths[varied_input]) + _bits(output, output_width))
        labels.append(label)
    names = tuple(
        [f"{varied_input}[{index}]" for index in range(widths[varied_input])]
        + [f"output[{index}]" for index in range(output_width)]
    )
    return NeuralDataset(tuple(rows), tuple(labels), "black_box", seed, names)


def xor_differential_dataset(
    primitive: Cipher,
    input_differences: Mapping[str, int],
    *,
    samples: int,
    seed: int = 0,
) -> NeuralDataset:
    """Generate output pairs from an XOR difference or the random class.

    Label one uses the requested related-input pair.  Label zero uses an
    independently random second input, preserving the statistical meaning of
    the legacy generator without depending on NumPy or TensorFlow.
    """

    _positive_integer("samples", samples)
    widths = _widths(primitive)
    if set(input_differences) != set(widths):
        raise ValueError("input_differences must define every primitive input exactly once")
    for name, difference in input_differences.items():
        if not isinstance(difference, int) or isinstance(difference, bool):
            raise TypeError(f"difference for {name!r} must be an integer")
        if not 0 <= difference < (1 << widths[name]):
            raise ValueError(f"difference for {name!r} does not fit its input width")
    output_width = _output_width(primitive)
    random = Random(seed)
    rows: list[tuple[int, ...]] = []
    labels: list[int] = []
    for _ in range(samples):
        label = random.getrandbits(1)
        first = {name: random.getrandbits(width) for name, width in widths.items()}
        if label:
            second = {name: value ^ input_differences[name] for name, value in first.items()}
        else:
            second = {name: random.getrandbits(width) for name, width in widths.items()}
        first_output = primitive.evaluate(first)
        second_output = primitive.evaluate(second)
        if not isinstance(first_output, int) or not isinstance(second_output, int):
            raise TypeError("neural datasets currently require an integer-encoded output")
        rows.append(_bits(first_output, output_width) + _bits(second_output, output_width))
        labels.append(label)
    names = tuple(
        [f"output_0[{index}]" for index in range(output_width)]
        + [f"output_1[{index}]" for index in range(output_width)]
    )
    return NeuralDataset(tuple(rows), tuple(labels), "xor_differential", seed, names)
