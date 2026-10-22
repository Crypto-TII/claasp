"""Dependency-free strict-avalanche measurements for typed primitives."""

from __future__ import annotations

import pathlib
from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite, log2
from typing import TYPE_CHECKING, TextIO

from claasp.analysis.datasets import generate_random_dataset, packed_bit_width
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
        (True, ('primitive_family', 'input_name', 'sample_count', 'seed', 'probabilities', 'method', 'complete', 'round_probabilities', 'round_numbers', 'metric', 'threshold'))
    """

    primitive_family: str
    input_name: str
    sample_count: int
    seed: int
    probabilities: tuple[tuple[float, ...], ...]
    method: str = "empirical_paired_evaluation"
    complete: bool = False

    round_probabilities: tuple[tuple[tuple[float, ...], ...], ...] = ()
    round_numbers: tuple[int, ...] = ()
    metric: str = "probability"
    threshold: float = 0.01

    def __post_init__(self) -> None:
        _validate_metric(self.metric)
        if (
            isinstance(self.threshold, bool)
            or not isfinite(self.threshold)
            or not 0 <= self.threshold <= 1
        ):
            raise ValueError("threshold must be a finite tolerance between zero and one")
        if bool(self.round_numbers) != bool(self.round_probabilities):
            raise ValueError("round numbers and matrices must be supplied together")
        if (
            len(self.round_numbers) != len(self.round_probabilities)
            or any(
                not isinstance(number, int) or isinstance(number, bool) or number < 1
                for number in self.round_numbers
            )
            or tuple(sorted(set(self.round_numbers))) != self.round_numbers
        ):
            raise ValueError("round numbers must be positive, unique, and increasing")
        if self.round_probabilities and self.round_probabilities[-1] != self.probabilities:
            raise ValueError("final round matrix must match probabilities")
        for matrix in (self.probabilities, *self.round_probabilities):
            if (
                not matrix
                or not matrix[0]
                or len(matrix) != len(self.probabilities)
                or any(len(row) != len(matrix[0]) for row in matrix)
            ):
                raise ValueError("avalanche matrices must be nonempty and rectangular")
            if any(not isfinite(value) or not 0 <= value <= 1 for row in matrix for value in row):
                raise ValueError("probabilities must be finite and between zero and one")

    def to_terminal(
        self, *, details: bool = False, metric: str | None = None, file: TextIO | None = None
    ) -> None:
        """Print metadata and round statistics; include bit matrices with details=True.

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

        to_terminal(avalanche_section(self, details=details, metric=metric), file=file)

    def plot(
        self,
        *,
        view: str = "summary",
        metric: str | None = None,
        style: str = "planes",
        show: bool = True,
        save_to: str | pathlib.Path | None = None,
    ) -> FigureArtifact:
        """Display round statistics, a heatmap, or opaque 3D round profiles.

        ``view`` is ``"summary"`` (default), ``"heatmap"``, or ``"3d"``.
        ``metric`` selects ``"probability"``, ``"entropy"``, or legacy ``"weight"``.
        For ``view="3d"``, ``style="planes"`` draws opaque filled profiles and
        ``style="dots"`` draws dots with a faint baseline for each round.
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

        return _plot_avalanche(
            self, view=view, metric=metric, style=style, show=show, save_to=save_to
        )

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
    metric: str = "probability",
    threshold: float = 0.01,
) -> AvalancheResult:
    """Estimate a primitive's strict-avalanche probability matrix.

    For each sampled input, the function evaluates a baseline and then flips
    each bit of ``input_name`` independently.  Randomness is reproducible and
    published round boundaries are read from
    :meth:`~claasp.graph.Primitive.evaluate_with_trace`.
    ``probabilities`` retains the final-output matrix; ``round_probabilities``
    retains all measured round matrices, numbered by ``round_numbers``.


    EXAMPLES::

        >>> try:
        ...     avalanche_probabilities()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    _validate_metric(metric)
    if isinstance(threshold, bool) or not isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("threshold must be a finite tolerance between zero and one")
    input_width = packed_bit_width(primitive, input_name)
    packed_bit_width(primitive)  # Reject non-binary output encodings.
    samples = generate_random_dataset(
        primitive, number_of_samples, seed=seed, fixed_inputs=fixed_inputs
    )
    final_number = primitive.details().number_of_rounds
    setup_rounds = max(0, len(primitive.graph.rounds) - final_number)
    outputs = [
        (number + 1 - setup_rounds, selections)
        for number, selections in primitive.graph.round_output_boundaries
        if number + 1 > setup_rounds
    ]
    final_output = primitive.graph.output
    assert final_output is not None
    if outputs and outputs[-1][0] == final_number:
        outputs[-1] = (final_number, (final_output,))
    else:
        outputs.append((final_number, (final_output,)))
    widths = []
    for _, selections in outputs:
        width = 0
        for selection in selections:
            unit_width = selection.array_type.unit_type.encoded_bit_size
            if unit_width is None:
                raise TypeError("avalanche round outputs require fixed-width binary encodings")
            width += unit_width * selection.array_type.unit_count
        widths.append(width)
    counts = [[[0] * width for _ in range(input_width)] for width in widths]

    def packed_outputs(execution):
        packed = []
        for _, selections in outputs:
            value = 0
            for selection in selections:
                unit_width = selection.array_type.unit_type.encoded_bit_size
                assert unit_width is not None
                for unit in primitive.graph.resolve_selection(selection, execution.values):
                    value = (value << unit_width) | unit
            packed.append(value)
        return packed

    for sample in samples.samples:
        inputs = dict(sample.inputs)
        baseline = packed_outputs(primitive.evaluate_with_trace(inputs))
        for input_bit in range(input_width):
            changed = dict(inputs)
            changed[input_name] ^= 1 << (input_width - input_bit - 1)
            changed_outputs = packed_outputs(primitive.evaluate_with_trace(changed))
            for round_index, (left, right, width) in enumerate(
                zip(baseline, changed_outputs, widths, strict=True)
            ):
                difference = left ^ right
                for output_bit in range(width):
                    counts[round_index][input_bit][output_bit] += (
                        difference >> (width - output_bit - 1)
                    ) & 1
    matrices = tuple(
        tuple(tuple(count / number_of_samples for count in row) for row in matrix)
        for matrix in counts
    )
    return AvalancheResult(
        primitive.family_name,
        input_name,
        number_of_samples,
        seed,
        matrices[-1],
        round_probabilities=matrices if final_number else (),
        round_numbers=tuple(number for number, _ in outputs) if final_number else (),
        metric=metric,
        threshold=threshold,
    )


def _validate_metric(metric: str) -> str:
    if metric not in {"probability", "entropy", "weight"}:
        raise ValueError("metric must be probability, entropy, or weight")
    return metric


def _metric_matrix(matrix, metric):
    _validate_metric(metric)
    if metric != "entropy":
        return matrix
    return tuple(
        tuple(
            0.0 if value in (0.0, 1.0) else -value * log2(value) - (1 - value) * log2(1 - value)
            for value in row
        )
        for row in matrix
    )


def _round_data(result):
    if result.round_probabilities:
        return tuple(zip(result.round_numbers, result.round_probabilities, strict=True))
    return ((None, result.probabilities),)


@dataclass(frozen=True)
class _RoundStatistics:
    number: int | None
    minimum: float
    maximum: float
    average: float
    minimum_positions: tuple[tuple[int, int], ...]
    maximum_positions: tuple[tuple[int, int], ...]
    satisfied: bool


def _criterion_bounds(metric, threshold):
    _validate_metric(metric)
    target = 1.0 if metric == "entropy" else 0.5
    return max(0.0, target - threshold), min(1.0, target + threshold)


def _round_statistics(result, metric):
    lower, upper = _criterion_bounds(metric, result.threshold)
    statistics = []
    for number, probabilities in _round_data(result):
        matrix = _metric_matrix(probabilities, metric)
        values = tuple(value for row in matrix for value in row)
        minimum, maximum = min(values), max(values)
        statistics.append(
            _RoundStatistics(
                number,
                minimum,
                maximum,
                sum(values) / len(values),
                tuple(
                    (i, o)
                    for i, row in enumerate(matrix)
                    for o, value in enumerate(row)
                    if value == minimum
                ),
                tuple(
                    (i, o)
                    for i, row in enumerate(matrix)
                    for o, value in enumerate(row)
                    if value == maximum
                ),
                minimum >= lower and maximum <= upper,
            )
        )
    return tuple(statistics)


def _round_profiles(result, metric):
    return tuple(
        tuple(sum(column) / len(matrix) for column in zip(*matrix, strict=True))
        for _, probabilities in _round_data(result)
        for matrix in (_metric_matrix(probabilities, metric),)
    )
