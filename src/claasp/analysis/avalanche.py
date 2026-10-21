"""Dependency-free strict-avalanche measurements for typed primitives."""

from __future__ import annotations

import pathlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, TextIO

from claasp.analysis.datasets import generate_avalanche_dataset
from claasp.graph import Primitive

if TYPE_CHECKING:
    from claasp.drivers.renderers.presentation import FigureArtifact


@dataclass(frozen=True, slots=True)
class AvalancheResult:
    """Estimated output-flip probabilities for every selected input bit.

    Rows and columns use the public packed integer's most-significant-bit-first
    order.  This is empirical evidence, not a proof of the strict avalanche
    criterion.


    EXAMPLES::

        >>> from dataclasses import fields
        >>> (AvalancheResult.__dataclass_params__.frozen, tuple(field.name for field in fields(AvalancheResult)))
        (True, ('primitive_family', 'input_name', 'sample_count', 'seed', 'probabilities', 'method', 'complete'))
    """

    primitive_family: str
    input_name: str
    sample_count: int
    seed: int
    probabilities: tuple[tuple[float, ...], ...]
    method: str = "empirical_paired_evaluation"
    complete: bool = False

    def to_terminal(self, *, file: TextIO | None = None) -> None:
        """Print the empirical metadata and probability matrix to a text stream.

        EXAMPLES::

            >>> from io import StringIO
            >>> result = AvalancheResult("example", "plaintext", 2, 9, ((0.5,),))
            >>> output = StringIO()
            >>> result.to_terminal(file=output)
            >>> "Avalanche summary" in output.getvalue()
            True
        """
        from claasp.presentation import avalanche_section
        from claasp.presentation._terminal import to_terminal

        to_terminal(avalanche_section(self), file=file)

    def plot(
        self, *, show: bool = True, save_to: str | pathlib.Path | None = None
    ) -> FigureArtifact:
        """Display a probability heatmap and return its figure artifact.

        ``show=False`` creates the plot without displaying it. ``save_to``
        saves the figure before display. Matplotlib is imported on demand;
        install the ``presentation`` extra to use this method. Analysis is
        never repeated, and no Matplotlib backend is selected here.

        EXAMPLES::

            >>> result = AvalancheResult("example", "plaintext", 2, 9, ((0.5,),))
            >>> callable(result.plot)
            True
        """
        from claasp.drivers.renderers.presentation import _plot_avalanche

        return _plot_avalanche(self, show=show, save_to=save_to)

    @property
    def input_bit_count(self) -> int:
        """Return the input bit count for this public typed contract."""

        return len(self.probabilities)

    @property
    def output_bit_count(self) -> int:
        """Return the output bit count for this public typed contract."""

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
    the underlying task uses only :meth:`~claasp.graph.Primitive.evaluate`.


    EXAMPLES::

        >>> try:
        ...     avalanche_probabilities()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
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

    probabilities = tuple(tuple(count / number_of_samples for count in row) for row in counts)
    return AvalancheResult(
        primitive.family_name, input_name, number_of_samples, seed, probabilities
    )
