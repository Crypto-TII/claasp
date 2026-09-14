"""Reproducible datasets produced through a primitive's public evaluator."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from random import Random

from claasp_next.graph import Primitive


@dataclass(frozen=True, slots=True)
class EvaluationSample:
    """One packed-input evaluation sample."""

    inputs: tuple[tuple[str, int], ...]
    output: int

    def input(self, name: str) -> int:
        """Return the packed value of input ``name``."""

        try:
            return dict(self.inputs)[name]
        except KeyError as error:
            raise KeyError(f"sample input {name!r} does not exist") from error


@dataclass(frozen=True, slots=True)
class EvaluationDataset:
    """A reproducible collection of concrete primitive evaluations."""

    primitive_family: str
    seed: int
    samples: tuple[EvaluationSample, ...]
    method: str = "python_random_v1"


@dataclass(frozen=True, slots=True)
class AvalancheSample:
    """One output difference caused by one MSB-first input-bit flip."""

    inputs: tuple[tuple[str, int], ...]
    input_bit: int
    output_difference: int


@dataclass(frozen=True, slots=True)
class AvalancheDataset:
    """Paired-evaluation data suitable for avalanche or randomness tests."""

    primitive_family: str
    input_name: str
    input_bit_count: int
    output_bit_count: int
    sample_count: int
    seed: int
    records: tuple[AvalancheSample, ...]
    method: str = "paired_evaluation_msb_first_v1"


def packed_bit_width(primitive: Primitive, input_name: str | None = None) -> int:
    """Return an encoded boundary width, rejecting non-binary encodings."""

    value_type = primitive.output.value_type if input_name is None and primitive.output else None
    if input_name is not None:
        try:
            value_type = primitive.inputs[input_name].value_type
        except KeyError as error:
            raise KeyError(f"primitive input {input_name!r} does not exist") from error
    if value_type is None:
        raise ValueError("primitive has no output")
    unit_width = value_type.domain.encoded_bit_size
    if unit_width is None:
        raise TypeError("dataset generation requires a fixed-width binary encoding")
    return unit_width * value_type.unit_count


def generate_random_dataset(
    primitive: Primitive,
    number_of_samples: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> EvaluationDataset:
    """Evaluate reproducible uniform packed inputs.

    ``fixed_inputs`` is useful for sampling plaintexts under one fixed key.
    The generator is local to this call and never changes Python's global
    random state.
    """

    if not isinstance(number_of_samples, int) or isinstance(number_of_samples, bool):
        raise TypeError("number_of_samples must be an integer")
    if number_of_samples <= 0:
        raise ValueError("number_of_samples must be positive")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")
    fixed = dict(fixed_inputs or {})
    unexpected = set(fixed) - set(primitive.inputs)
    if unexpected:
        raise ValueError(f"unknown fixed inputs: {sorted(unexpected)}")

    widths = {name: packed_bit_width(primitive, name) for name in primitive.inputs}
    random = Random(seed)
    samples = []
    for _ in range(number_of_samples):
        inputs = {
            name: fixed[name] if name in fixed else random.getrandbits(width)
            for name, width in widths.items()
        }
        output = primitive.evaluate(inputs)
        if not isinstance(output, int):
            raise TypeError("dataset generation requires a packed integer output")
        samples.append(EvaluationSample(tuple(inputs.items()), output))
    return EvaluationDataset(primitive.family_name, seed, tuple(samples))


def generate_avalanche_dataset(
    primitive: Primitive,
    input_name: str,
    number_of_samples: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> AvalancheDataset:
    """Generate output differences for every one-bit input perturbation."""

    input_width = packed_bit_width(primitive, input_name)
    output_width = packed_bit_width(primitive)
    baselines = generate_random_dataset(
        primitive, number_of_samples, seed=seed, fixed_inputs=fixed_inputs
    )
    records = []
    for sample in baselines.samples:
        baseline_inputs = dict(sample.inputs)
        for input_bit in range(input_width):
            changed_inputs = dict(baseline_inputs)
            changed_inputs[input_name] ^= 1 << (input_width - input_bit - 1)
            changed_output = primitive.evaluate(changed_inputs)
            if not isinstance(changed_output, int):
                raise TypeError("avalanche datasets require a packed integer output")
            records.append(AvalancheSample(
                sample.inputs, input_bit, sample.output ^ changed_output
            ))
    return AvalancheDataset(
        primitive.family_name,
        input_name,
        input_width,
        output_width,
        number_of_samples,
        seed,
        tuple(records),
    )
