"""Lazy, reproducible statistical dataset families.

These generators retain the useful final-output semantics of CLAASP's legacy
correlation, CBC, and density datasets without requiring NumPy.  A dataset is
re-iterable: every iteration reconstructs the same local pseudo-random stream.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from itertools import combinations
from math import ceil, comb
from random import Random

from claasp_next.analysis.datasets import packed_bit_width
from claasp_next.graph import Cipher


@dataclass(frozen=True, slots=True)
class StatisticalRecord:
    """One packed value in a statistical test sequence."""

    sample: int
    block: int
    value: int


@dataclass(frozen=True, slots=True)
class StatisticalDataset:
    """A lazy deterministic dataset backed by public primitive evaluation."""

    primitive: Cipher
    kind: str
    input_name: str
    sample_count: int
    block_count: int
    seed: int
    ratio: float = 1.0
    fixed_inputs: tuple[tuple[str, int], ...] = ()
    method: str = "python_random_stream_v1"

    @property
    def output_bit_count(self) -> int:
        return packed_bit_width(self.primitive)

    def __iter__(self) -> Iterator[StatisticalRecord]:
        if self.kind == "correlation":
            return self._correlation_records()
        if self.kind == "cbc":
            return self._cbc_records()
        if self.kind in {"low_density", "high_density"}:
            return self._density_records()
        raise RuntimeError(f"unsupported statistical dataset kind {self.kind!r}")

    def iter_bytes(self) -> Iterator[bytes]:
        """Yield fixed-width big-endian records without materializing them."""

        width = self.output_bit_count
        if width % 8:
            raise ValueError("byte serialization requires an output width divisible by eight")
        size = width // 8
        for record in self:
            yield record.value.to_bytes(size, "big")

    def iter_selected_inputs(self) -> Iterator[int]:
        """Yield the selected input sequence for a density dataset."""

        if self.kind not in {"low_density", "high_density"}:
            raise TypeError("selected-input enumeration is only defined for density datasets")
        return self._density_inputs()

    def _random_other_inputs(self, random: Random) -> dict[str, int]:
        fixed = dict(self.fixed_inputs)
        return {
            name: fixed[name] if name in fixed else random.getrandbits(packed_bit_width(self.primitive, name))
            for name in self.primitive.inputs
            if name != self.input_name
        }

    def _correlation_records(self) -> Iterator[StatisticalRecord]:
        random = Random(self.seed)
        width = packed_bit_width(self.primitive, self.input_name)
        selected_values = tuple(random.getrandbits(width) for _ in range(self.block_count))
        for sample in range(self.sample_count):
            other_inputs = self._random_other_inputs(random)
            for block, selected in enumerate(selected_values):
                inputs = dict(other_inputs)
                inputs[self.input_name] = selected
                output = self.primitive.evaluate(inputs)
                if not isinstance(output, int):
                    raise TypeError("statistical datasets require a packed integer output")
                yield StatisticalRecord(sample, block, output ^ selected)

    def _cbc_records(self) -> Iterator[StatisticalRecord]:
        random = Random(self.seed)
        for sample in range(self.sample_count):
            other_inputs = self._random_other_inputs(random)
            chaining_value = 0
            for block in range(self.block_count):
                inputs = dict(other_inputs)
                inputs[self.input_name] = chaining_value
                output = self.primitive.evaluate(inputs)
                if not isinstance(output, int):
                    raise TypeError("statistical datasets require a packed integer output")
                yield StatisticalRecord(sample, block, output)
                chaining_value = output

    def _density_inputs(self) -> Iterator[int]:
        width = packed_bit_width(self.primitive, self.input_name)
        complement = self.kind == "high_density"
        mask = (1 << width) - 1
        yield mask if complement else 0
        for position in range(width):
            value = 1 << (width - position - 1)
            yield value ^ mask if complement else value

        total = comb(width, 2)
        selected_count = ceil(total * self.ratio)
        selected = set(Random(self.seed).sample(range(total), selected_count))
        for index, (left, right) in enumerate(combinations(range(width), 2)):
            if index in selected:
                value = (1 << (width - left - 1)) | (1 << (width - right - 1))
                yield value ^ mask if complement else value

    def _density_records(self) -> Iterator[StatisticalRecord]:
        random = Random(self.seed)
        for sample in range(self.sample_count):
            other_inputs = self._random_other_inputs(random)
            for block, selected in enumerate(self._density_inputs()):
                inputs = dict(other_inputs)
                inputs[self.input_name] = selected
                output = self.primitive.evaluate(inputs)
                if not isinstance(output, int):
                    raise TypeError("statistical datasets require a packed integer output")
                yield StatisticalRecord(sample, block, output)


def correlation_dataset(
    primitive: Cipher,
    input_name: str,
    number_of_samples: int,
    blocks_per_sample: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Return output XOR selected-input records, as in the legacy generator."""

    if packed_bit_width(primitive, input_name) != packed_bit_width(primitive):
        raise ValueError("correlation datasets require selected input and output widths to match")

    return _dataset(
        primitive, "correlation", input_name, number_of_samples,
        blocks_per_sample, seed, 1.0, fixed_inputs,
    )


def cbc_dataset(
    primitive: Cipher,
    input_name: str,
    number_of_samples: int,
    blocks_per_sample: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Return zero-IV output-feedback sequences for a width-matched input."""

    if packed_bit_width(primitive, input_name) != packed_bit_width(primitive):
        raise ValueError("CBC datasets require selected input and output widths to match")
    return _dataset(
        primitive, "cbc", input_name, number_of_samples,
        blocks_per_sample, seed, 1.0, fixed_inputs,
    )


def low_density_dataset(
    primitive: Cipher,
    input_name: str,
    number_of_samples: int,
    *,
    ratio: float = 1.0,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Evaluate weight-zero, weight-one, and sampled weight-two inputs."""

    return _density_dataset(
        primitive, "low_density", input_name, number_of_samples, ratio, seed, fixed_inputs
    )


def high_density_dataset(
    primitive: Cipher,
    input_name: str,
    number_of_samples: int,
    *,
    ratio: float = 1.0,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Evaluate complements of the corresponding low-density inputs."""

    return _density_dataset(
        primitive, "high_density", input_name, number_of_samples, ratio, seed, fixed_inputs
    )


def _density_dataset(primitive, kind, input_name, samples, ratio, seed, fixed_inputs):
    if not isinstance(ratio, (int, float)) or isinstance(ratio, bool) or not 0 <= ratio <= 1:
        raise ValueError("ratio must be between zero and one")
    width = packed_bit_width(primitive, input_name)
    blocks = 1 + width + ceil(comb(width, 2) * ratio)
    return _dataset(primitive, kind, input_name, samples, blocks, seed, float(ratio), fixed_inputs)


def _dataset(primitive, kind, input_name, samples, blocks, seed, ratio, fixed_inputs):
    packed_bit_width(primitive, input_name)
    for name in ("number_of_samples", "blocks_per_sample"):
        value = samples if name == "number_of_samples" else blocks
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")
    fixed = dict(fixed_inputs or {})
    unexpected = set(fixed) - (set(primitive.inputs) - {input_name})
    if unexpected:
        raise ValueError(f"fixed_inputs contains selected or unknown inputs: {sorted(unexpected)}")
    return StatisticalDataset(
        primitive, kind, input_name, samples, blocks, seed, ratio, tuple(fixed.items())
    )
