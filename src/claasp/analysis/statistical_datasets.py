"""Lazy, reproducible statistical dataset families.

These generators retain the useful final-output semantics of CLAASP's legacy
avalanche, correlation, CBC, random, and density datasets without requiring NumPy. A dataset is
re-iterable: every iteration reconstructs the same local pseudo-random stream.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations
from math import ceil, comb
from random import Random
from typing import BinaryIO

from claasp.analysis.datasets import packed_bit_width
from claasp.graph import Primitive


@dataclass(frozen=True, slots=True)
class StatisticalRecord:
    """One packed value in a statistical test sequence.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (StatisticalRecord.__dataclass_params__.frozen, tuple(field.name for field in fields(StatisticalRecord)))
        (True, ('sample', 'block', 'value'))
    """

    sample: int
    block: int
    value: int


@dataclass(frozen=True, slots=True)
class StatisticalDatasetManifest:
    """Portable identity and provenance for one serialized byte stream.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (StatisticalDatasetManifest.__dataclass_params__.frozen, tuple(field.name for field in fields(StatisticalDatasetManifest)))
        (True, ('schema_version', 'primitive', 'realization', 'execution_engine', 'kind', 'input_name', 'sample_count', 'block_count', 'record_count', 'output_bit_count', 'byte_count', 'seed', 'ratio', 'fixed_inputs', 'method', 'bit_order', 'byte_order', 'record_order', 'serialization', 'sha256'))
    """

    schema_version: int
    primitive: str
    realization: str
    execution_engine: str
    kind: str
    input_name: str
    sample_count: int
    block_count: int
    record_count: int
    output_bit_count: int
    byte_count: int
    seed: int
    ratio: float
    fixed_inputs: tuple[tuple[str, int], ...]
    method: str
    bit_order: str
    byte_order: str
    record_order: str
    serialization: str
    sha256: str

    def to_json(self) -> str:
        """Return deterministic UTF-8 JSON terminated by one newline."""

        payload = {field: getattr(self, field) for field in self.__dataclass_fields__}
        payload["fixed_inputs"] = dict(self.fixed_inputs)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


@dataclass(frozen=True, slots=True)
class StatisticalDataset:
    """A lazy deterministic dataset backed by public primitive evaluation.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (StatisticalDataset.__dataclass_params__.frozen, tuple(field.name for field in fields(StatisticalDataset)))
        (True, ('primitive', 'kind', 'input_name', 'sample_count', 'block_count', 'seed', 'ratio', 'fixed_inputs', 'method'))
    """

    primitive: Primitive
    kind: str
    input_name: str
    sample_count: int
    block_count: int
    seed: int
    ratio: float = 1.0
    fixed_inputs: tuple[tuple[str, int], ...] = ()
    method: str = "python_random_stream_v1"

    @property
    def record_count(self) -> int:
        """Return the record count for this public typed contract."""

        return self.sample_count * self.block_count

    @property
    def output_bit_count(self) -> int:
        """Return the output bit count for this public typed contract."""

        return packed_bit_width(self.primitive)

    def __iter__(self) -> Iterator[StatisticalRecord]:
        if self.kind == "avalanche":
            return self._avalanche_records()
        if self.kind == "correlation":
            return self._correlation_records()
        if self.kind == "cbc":
            return self._cbc_records()
        if self.kind == "random":
            return self._random_records()
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

    def write_binary(self, stream: BinaryIO) -> int:
        """Write raw fixed-width records to ``stream`` and return byte count."""

        written = 0
        for chunk in self.iter_bytes():
            result = stream.write(chunk)
            if result is not None and result != len(chunk):
                raise OSError("statistical dataset stream accepted a partial record")
            written += len(chunk)
        return written

    def digest(self) -> str:
        """Return SHA-256 of the exact raw byte stream without materializing it."""

        digest = sha256()
        for chunk in self.iter_bytes():
            digest.update(chunk)
        return digest.hexdigest()

    def manifest(self) -> StatisticalDatasetManifest:
        """Describe the stream construction, encoding, provenance, and hash."""

        realization = getattr(getattr(self.primitive, "realization", None), "name", "default")
        byte_count = self.record_count * (self.output_bit_count // 8)
        return StatisticalDatasetManifest(
            schema_version=2,
            primitive=self.primitive.family_name,
            realization=realization,
            execution_engine="python_scalar",
            kind=self.kind,
            input_name=self.input_name,
            sample_count=self.sample_count,
            block_count=self.block_count,
            record_count=self.record_count,
            output_bit_count=self.output_bit_count,
            byte_count=byte_count,
            seed=self.seed,
            ratio=self.ratio,
            fixed_inputs=self.fixed_inputs,
            method=self.method,
            bit_order="msb_first",
            byte_order="big",
            record_order="sample_major_then_block",
            serialization="raw_fixed_width_outputs_v1",
            sha256=self.digest(),
        )

    def iter_selected_inputs(self) -> Iterator[int]:
        """Yield the selected input sequence for a density dataset."""

        if self.kind not in {"low_density", "high_density"}:
            raise TypeError("selected-input enumeration is only defined for density datasets")
        return self._density_inputs()

    def _random_other_inputs(self, random: Random) -> dict[str, int]:
        fixed = dict(self.fixed_inputs)
        return {
            name: fixed[name]
            if name in fixed
            else random.getrandbits(packed_bit_width(self.primitive, name))
            for name in self.primitive.graph.input_arrays
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

    def _avalanche_records(self) -> Iterator[StatisticalRecord]:
        random = Random(self.seed)
        width = packed_bit_width(self.primitive, self.input_name)
        fixed = dict(self.fixed_inputs)
        for sample in range(self.sample_count):
            inputs = {
                name: (random.getrandbits(width) if name == self.input_name else fixed.get(name, 0))
                for name, width in (
                    (name, packed_bit_width(self.primitive, name))
                    for name in self.primitive.graph.input_arrays
                )
            }
            baseline = self.primitive.evaluate(inputs)
            if not isinstance(baseline, int):
                raise TypeError("statistical datasets require a packed integer output")
            for bit in range(width):
                changed = dict(inputs)
                changed[self.input_name] ^= 1 << (width - bit - 1)
                output = self.primitive.evaluate(changed)
                if not isinstance(output, int):
                    raise TypeError("statistical datasets require a packed integer output")
                yield StatisticalRecord(sample, bit, baseline ^ output)

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

    def _random_records(self) -> Iterator[StatisticalRecord]:
        random = Random(self.seed)
        selected_width = packed_bit_width(self.primitive, self.input_name)
        for sample in range(self.sample_count):
            other_inputs = self._random_other_inputs(random)
            for block in range(self.block_count):
                inputs = dict(other_inputs)
                inputs[self.input_name] = random.getrandbits(selected_width)
                output = self.primitive.evaluate(inputs)
                if not isinstance(output, int):
                    raise TypeError("statistical datasets require a packed integer output")
                yield StatisticalRecord(sample, block, output)

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
    primitive: Primitive,
    input_name: str,
    number_of_samples: int,
    blocks_per_sample: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Return output XOR selected-input records, as in the legacy generator.

    EXAMPLES::

        >>> try:
        ...     correlation_dataset()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if packed_bit_width(primitive, input_name) != packed_bit_width(primitive):
        raise ValueError("correlation datasets require selected input and output widths to match")

    return _dataset(
        primitive,
        "correlation",
        input_name,
        number_of_samples,
        blocks_per_sample,
        seed,
        1.0,
        fixed_inputs,
    )


def avalanche_statistical_dataset(
    primitive: Primitive,
    input_name: str,
    number_of_samples: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Return one output difference per selected-input bit and sample.

    EXAMPLES::

        >>> callable(avalanche_statistical_dataset)
        True
    """

    blocks = packed_bit_width(primitive, input_name)
    return _dataset(
        primitive,
        "avalanche",
        input_name,
        number_of_samples,
        blocks,
        seed,
        1.0,
        fixed_inputs,
    )


def cbc_dataset(
    primitive: Primitive,
    input_name: str,
    number_of_samples: int,
    blocks_per_sample: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Return zero-IV output-feedback sequences for a width-matched input.

    EXAMPLES::

        >>> try:
        ...     cbc_dataset()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if packed_bit_width(primitive, input_name) != packed_bit_width(primitive):
        raise ValueError("CBC datasets require selected input and output widths to match")
    return _dataset(
        primitive,
        "cbc",
        input_name,
        number_of_samples,
        blocks_per_sample,
        seed,
        1.0,
        fixed_inputs,
    )


def random_statistical_dataset(
    primitive: Primitive,
    input_name: str,
    number_of_samples: int,
    blocks_per_sample: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Return outputs for random selected inputs and sample-fixed other inputs.

    EXAMPLES::

        >>> callable(random_statistical_dataset)
        True
    """

    return _dataset(
        primitive,
        "random",
        input_name,
        number_of_samples,
        blocks_per_sample,
        seed,
        1.0,
        fixed_inputs,
    )


def low_density_dataset(
    primitive: Primitive,
    input_name: str,
    number_of_samples: int,
    *,
    ratio: float = 1.0,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Evaluate weight-zero, weight-one, and sampled weight-two inputs.

    EXAMPLES::

        >>> try:
        ...     low_density_dataset()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    return _density_dataset(
        primitive, "low_density", input_name, number_of_samples, ratio, seed, fixed_inputs
    )


def high_density_dataset(
    primitive: Primitive,
    input_name: str,
    number_of_samples: int,
    *,
    ratio: float = 1.0,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> StatisticalDataset:
    """Evaluate complements of the corresponding low-density inputs.

    EXAMPLES::

        >>> try:
        ...     high_density_dataset()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

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
    unexpected = set(fixed) - (set(primitive.graph.input_arrays) - {input_name})
    if unexpected:
        raise ValueError(f"fixed_inputs contains selected or unknown inputs: {sorted(unexpected)}")
    return StatisticalDataset(
        primitive, kind, input_name, samples, blocks, seed, ratio, tuple(sorted(fixed.items()))
    )


@dataclass(frozen=True, slots=True)
class SuppliedStatisticalDataset:
    """An immutable packed stream supplied independently of a primitive.

    Bytes are packed most-significant bit first. ``from_bits`` accepts a flat
    iterable of bits, including a one-dimensional NumPy array. File input is
    explicitly either packed binary or whitespace-separated ASCII bits.

    EXAMPLES::

        >>> dataset = SuppliedStatisticalDataset.from_bits([1, 0] * 4)
        >>> dataset.data.hex(), dataset.bit_count
        ('aa', 8)
    """

    data: bytes
    bit_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("data must be immutable packed bytes")
        if type(self.bit_count) is not int or not 0 < self.bit_count <= 8 * len(self.data):
            raise ValueError("bit_count must be positive and fit the packed stream")
        if len(self.data) != (self.bit_count + 7) // 8:
            raise ValueError("packed stream contains unused bytes")
        padding = (-self.bit_count) % 8
        if padding and self.data[-1] & ((1 << padding) - 1):
            raise ValueError("unused trailing bits must be zero")

    @classmethod
    def from_bits(cls, bits) -> SuppliedStatisticalDataset:
        """Pack a flat bit iterable, rejecting non-binary or empty input.

        EXAMPLES::

            >>> dataset = SuppliedStatisticalDataset.from_bits([1, 0, 1])
            >>> dataset.data.hex(), dataset.bit_count
            ('a0', 3)

        The final byte is zero-padded; bit_count keeps those padding bits out
        of statistical calculations.
        """
        from operator import index

        packed = bytearray()
        value = count = 0
        for bit in bits:
            try:
                bit = index(bit)
            except TypeError as error:
                raise ValueError(
                    "bits must be a flat iterable of integer zeros and ones"
                ) from error
            if bit not in (0, 1):
                raise ValueError("bits must contain only zeros and ones")
            value = (value << 1) | bit
            count += 1
            if count % 8 == 0:
                packed.append(value)
                value = 0
        if count % 8:
            packed.append(value << (-count % 8))
        return cls(bytes(packed), count)

    @classmethod
    def from_file(cls, path, *, input_format: str = "binary") -> SuppliedStatisticalDataset:
        """Read packed binary or ASCII bits without guessing the file format.

        EXAMPLES::

            >>> from pathlib import Path
            >>> from tempfile import TemporaryDirectory
            >>> with TemporaryDirectory() as directory:
            ...     path = Path(directory) / "bits.txt"
            ...     _ = path.write_text("101 010", encoding="ascii")
            ...     dataset = SuppliedStatisticalDataset.from_file(path, input_format="ascii")
            ...     print(dataset.data.hex(), dataset.bit_count)
            a8 6

        Binary files use all eight bits of every byte; ASCII input preserves
        the exact number of zero/one characters and ignores whitespace.
        """
        from pathlib import Path

        data = Path(path).read_bytes()
        if input_format == "binary":
            return cls(data, len(data) * 8)
        if input_format != "ascii":
            raise ValueError("input_format must be binary or ascii")
        compact = b"".join(data.split())
        if any(bit not in (48, 49) for bit in compact):
            raise ValueError("ASCII input must contain only bits and whitespace")
        return cls.from_bits(bit - 48 for bit in compact)

    def write_binary(self, stream: BinaryIO) -> int:
        """Write the packed stream, including zero padding in the final byte."""
        written = stream.write(self.data)
        if written is not None and written != len(self.data):
            raise OSError("stream accepted only part of the supplied dataset")
        return len(self.data)

    def digest(self) -> str:
        """Return SHA-256 of packed bytes (bit_count identifies final padding)."""
        return sha256(self.data).hexdigest()
