"""Dependency-free strict-avalanche measurements for typed primitives."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from claasp_next.analysis.datasets import generate_avalanche_dataset
from claasp_next.graph import Primitive


@dataclass(frozen=True, slots=True)
class AvalancheResult:
    """Estimated output-flip probabilities for every selected input bit.

    Rows and columns use the public packed integer's most-significant-bit-first
    order.  This is empirical evidence, not a proof of the strict avalanche
    criterion.
    """

    primitive_family: str
    input_name: str
    sample_count: int
    seed: int
    probabilities: tuple[tuple[float, ...], ...]
    method: str = "empirical_paired_evaluation"
    complete: bool = False

    @property
    def input_bit_count(self) -> int:
        return len(self.probabilities)

    @property
    def output_bit_count(self) -> int:
        return len(self.probabilities[0]) if self.probabilities else 0

    @property
    def mean_changed_output_bits(self) -> tuple[float, ...]:
        """Expected output Hamming weight for each one-bit input change."""

        return tuple(sum(row) for row in self.probabilities)

    @property
    def maximum_sac_bias(self) -> float:
        """Largest observed absolute deviation from probability one half."""

        return max(abs(probability - 0.5) for row in self.probabilities for probability in row)


def avalanche_probabilities(
    primitive: Primitive,
    input_name: str,
    number_of_samples: int,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
) -> AvalancheResult:
    """Estimate a primitive's strict-avalanche probability matrix.

    For each sampled input, the function evaluates a baseline and then flips
    each bit of ``input_name`` independently.  Randomness is reproducible and
    the underlying task uses only :meth:`~claasp_next.graph.Primitive.evaluate`.
    """

    dataset = generate_avalanche_dataset(
        primitive, input_name, number_of_samples, seed=seed, fixed_inputs=fixed_inputs
    )
    counts = [[0] * dataset.output_bit_count for _ in range(dataset.input_bit_count)]
    for record in dataset.records:
        for output_bit in range(dataset.output_bit_count):
            counts[record.input_bit][output_bit] += (
                record.output_difference >> (dataset.output_bit_count - output_bit - 1)
            ) & 1

    probabilities = tuple(
        tuple(count / number_of_samples for count in row) for row in counts
    )
    return AvalancheResult(
        primitive.family_name, input_name, number_of_samples, seed, probabilities
    )
