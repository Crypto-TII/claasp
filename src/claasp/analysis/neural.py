"""Framework-independent contracts for neural distinguisher experiments.

This module deliberately generates ordinary Python data.  NumPy tensors and
framework-specific models belong in optional drivers, not in CLAASP's core.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from random import Random
from typing import Protocol

from claasp.encoding import bits_from_int
from claasp.graph import Primitive


def _positive_integer(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _bits(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> shift) & 1 for shift in range(width - 1, -1, -1))


def _component_ids(component_ids: str | Sequence[str]) -> tuple[str, ...]:
    ids = (component_ids,) if isinstance(component_ids, str) else tuple(component_ids)
    if not ids:
        raise ValueError("component_ids must not be empty")
    return ids


def _projection_width(primitive: Primitive, component_ids: tuple[str, ...]) -> int:
    total = 0
    for component_id in component_ids:
        width = primitive.graph.port(component_id).array_type.encoded_bit_size
        if width is None:
            raise ValueError(f"{component_id!r} is not canonically bit-encoded")
        total += width
    return total


def _trace_bits(primitive: Primitive, source_id: str, value: tuple[int, ...]) -> tuple[int, ...]:
    """Flatten one execution-trace value into canonical MSB-first bits.

    ``value`` holds one integer per logical unit in the domain declared for
    ``source_id`` (for example one 16-bit word per Speck state half); each
    unit is expanded to its own canonical bit width and the results are
    concatenated in order, matching the flat encoding every other dataset in
    this module uses for primitive inputs and outputs.
    """

    scalar_width = primitive.graph.port(source_id).array_type.domain.encoded_bit_size
    if scalar_width is None:
        raise ValueError(f"{source_id!r} is not canonically bit-encoded")
    bits: list[int] = []
    for unit in value:
        bits.extend(bits_from_int(unit, scalar_width))
    return tuple(bits)


def _projection_bits(
    primitive: Primitive, component_ids: tuple[str, ...], trace
) -> tuple[int, ...]:
    return tuple(
        bit
        for component_id in component_ids
        for bit in _trace_bits(primitive, component_id, trace.value_of(component_id))
    )


def _widths(primitive: Primitive) -> dict[str, int]:
    widths = {
        name: port.array_type.encoded_bit_size for name, port in primitive.graph.input_ports.items()
    }
    if any(width is None for width in widths.values()):
        raise ValueError("neural datasets require canonically bit-encoded inputs")
    return {name: int(width) for name, width in widths.items()}


def _output_width(primitive: Primitive) -> int:
    if primitive.graph.output is None:
        raise ValueError("the primitive must declare an output")
    width = primitive.graph.output.array_type.encoded_bit_size
    if width is None:
        raise ValueError("neural datasets require a canonically bit-encoded output")
    return width


@dataclass(frozen=True, slots=True)
class NeuralDataset:
    """Binary features and labels with reproducibility metadata.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NeuralDataset.__dataclass_params__.frozen, tuple(field.name for field in fields(NeuralDataset)))
        (True, ('features', 'labels', 'kind', 'seed', 'feature_names'))
    """

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
        """Return the sample count for this public typed contract."""

        return len(self.labels)

    @property
    def feature_width(self) -> int:
        """Return the feature width for this public typed contract."""

        return len(self.features[0]) if self.features else len(self.feature_names)


@dataclass(frozen=True, slots=True)
class NeuralExperiment:
    """Portable training request consumed by an optional ML driver.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NeuralExperiment.__dataclass_params__.frozen, tuple(field.name for field in fields(NeuralExperiment)))
        (True, ('architecture', 'epochs', 'batch_size', 'validation_fraction', 'seed'))
    """

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
    """Framework-neutral summary returned by neural training drivers.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (NeuralExperimentResult.__dataclass_params__.frozen, tuple(field.name for field in fields(NeuralExperimentResult)))
        (True, ('validation_accuracy', 'driver', 'deterministic'))
    """

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

    def train(self, dataset: NeuralDataset, experiment: NeuralExperiment) -> NeuralExperimentResult:
        """Train and return one typed neural experiment result."""

        ...


def black_box_dataset(
    primitive: Primitive,
    varied_input: str,
    *,
    samples: int,
    seed: int = 0,
) -> NeuralDataset:
    """Generate the legacy ``L || real-or-random-output`` experiment.

    Other primitive inputs are fixed for the whole dataset, matching the
    black-box experiment in CLAASP 4.  Bit order is most-significant first.


    EXAMPLES::

        >>> try:
        ...     black_box_dataset()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
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
    primitive: Primitive,
    input_differences: Mapping[str, int],
    *,
    samples: int,
    seed: int = 0,
) -> NeuralDataset:
    """Generate output pairs from an XOR difference or the random class.

    Label one uses the requested related-input pair.  Label zero uses an
    independently random second input, preserving the statistical meaning of
    the legacy generator without depending on NumPy or TensorFlow.


    EXAMPLES::

        >>> try:
        ...     xor_differential_dataset()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
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


def round_component_ids(primitive: Primitive, round_number: int) -> tuple[str, ...]:
    """Return every component id CLAASP added within one round of ``primitive``.

    A convenience selector for :func:`component_output_dataset` and
    :func:`xor_differential_component_dataset`.  Passing this tuple as their
    ``component_ids`` argument projects the primitive's full round state
    (round output and, where the primitive interleaves it in the same round,
    the round key), mirroring legacy's ``round_output``/``round_key_output``
    intermediate-output components (see
    ``claasp.cipher_modules.neural_network_tests``) without requiring the
    graph to declare an explicit concatenated intermediate-output component.
    Callers that need only the state or only the key schedule can filter the
    returned ids (for example by a primitive's own component-id prefix
    convention) before passing them on.


    EXAMPLES::

        >>> try:
        ...     round_component_ids()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    rounds = primitive.graph.rounds
    if not isinstance(round_number, int) or isinstance(round_number, bool):
        raise TypeError("round_number must be an integer")
    if not 0 <= round_number < len(rounds):
        raise ValueError(f"round_number must be in range({len(rounds)})")
    return tuple(component.component_id for component in rounds[round_number].components)


def component_output_dataset(
    primitive: Primitive,
    varied_input: str,
    component_ids: str | Sequence[str],
    *,
    samples: int,
    seed: int = 0,
) -> NeuralDataset:
    """Generate a black-box dataset labeled by an intermediate trace value.

    Generalizes :func:`black_box_dataset` to any value captured by the
    primitive's :class:`~claasp.annotations.ExecutionTrace` instead of
    only its final ``evaluate()`` output -- covering legacy's ability to
    target a specific round's state (``round_output``), a round key
    (``round_key_output``), or an arbitrary component id (see
    ``claasp.cipher_modules.neural_network_tests._update_component_output_ids``).
    Pass one component id to target a single component, or a sequence --
    such as :func:`round_component_ids` -- to concatenate several into one
    composite projection, the way legacy round/round-key intermediate
    outputs can span more than one wire.

    Label one uses the primitive's real projected value; label zero
    substitutes independently random bits of the same width, preserving the
    legacy black-box construction described in :func:`black_box_dataset`.


    EXAMPLES::

        >>> try:
        ...     component_output_dataset()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    _positive_integer("samples", samples)
    widths = _widths(primitive)
    if varied_input not in widths:
        raise ValueError(f"unknown primitive input {varied_input!r}")
    ids = _component_ids(component_ids)
    target_width = _projection_width(primitive, ids)
    random = Random(seed)
    fixed = {name: random.getrandbits(width) for name, width in widths.items()}
    rows: list[tuple[int, ...]] = []
    labels: list[int] = []
    for _ in range(samples):
        label = random.getrandbits(1)
        varied_value = random.getrandbits(widths[varied_input])
        inputs = dict(fixed)
        inputs[varied_input] = varied_value
        if label:
            projection = _projection_bits(
                primitive, ids, primitive.evaluate_with_trace(inputs).trace
            )
        else:
            projection = tuple(random.getrandbits(1) for _ in range(target_width))
        rows.append(_bits(varied_value, widths[varied_input]) + projection)
        labels.append(label)
    target_name = "+".join(ids)
    names = tuple(
        [f"{varied_input}[{index}]" for index in range(widths[varied_input])]
        + [f"{target_name}[{index}]" for index in range(target_width)]
    )
    return NeuralDataset(tuple(rows), tuple(labels), "black_box", seed, names)


def xor_differential_component_dataset(
    primitive: Primitive,
    input_differences: Mapping[str, int],
    component_ids: str | Sequence[str],
    *,
    samples: int,
    seed: int = 0,
) -> NeuralDataset:
    """Generate XOR-differential pairs from an intermediate trace value.

    Generalizes :func:`xor_differential_dataset` the same way
    :func:`component_output_dataset` generalizes :func:`black_box_dataset`:
    the paired values come from a specific round's state, a round key, or an
    arbitrary component id captured by the typed execution trace, instead of
    only the primitive's final output.


    EXAMPLES::

        >>> try:
        ...     xor_differential_component_dataset()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
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
    ids = _component_ids(component_ids)
    target_width = _projection_width(primitive, ids)
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
        first_bits = _projection_bits(primitive, ids, primitive.evaluate_with_trace(first).trace)
        second_bits = _projection_bits(primitive, ids, primitive.evaluate_with_trace(second).trace)
        rows.append(first_bits + second_bits)
        labels.append(label)
    target_name = "+".join(ids)
    names = tuple(
        [f"{target_name}_0[{index}]" for index in range(target_width)]
        + [f"{target_name}_1[{index}]" for index in range(target_width)]
    )
    return NeuralDataset(tuple(rows), tuple(labels), "xor_differential", seed, names)
