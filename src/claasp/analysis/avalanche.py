"""Sample-parallel avalanche measurements and dependency-free derived metrics."""

from __future__ import annotations

import pathlib
from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite, log, log2, sqrt
from random import Random
from typing import TYPE_CHECKING, TextIO

from claasp.analysis.datasets import packed_bit_width
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
        (True, ('primitive_family', 'input_name', 'sample_count', 'seed', 'probabilities', 'method', 'complete', 'round_probabilities', 'round_numbers', 'metric', 'threshold', 'confidence'))
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
    threshold: float | None = None
    confidence: float = 0.95

    def __post_init__(self) -> None:
        _validate_metric(self.metric)
        _validate_reporting(self.threshold, self.confidence)
        if (
            not isinstance(self.sample_count, int)
            or isinstance(self.sample_count, bool)
            or self.sample_count <= 0
        ):
            raise ValueError("sample_count must be a positive integer")
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

        By default SAC compatibility uses the sample count and simultaneous
        confidence across all retained rounds/pairs. Explicit ``threshold``
        on the analysis result selects a fixed tolerance instead.

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
        ``metric`` selects ``"probability"``, ``"dependence"``, ``"entropy"``,
        or ``"weight"`` (per-bit probability contributions to weight).
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

    def vectors(self, metric: str = "probability") -> tuple[tuple[tuple[float, ...], ...], ...]:
        """Return round × flipped-input-bit × output-bit metric vectors.

        EXAMPLES::

            >>> result = AvalancheResult("demo", "state", 2, 0, ((0.0, 0.5),))
            >>> result.vectors("dependence")
            (((0.0, 1.0),),)
        """
        return tuple(_metric_matrix(matrix, metric) for _, matrix in _round_data(self))

    def dependence(self) -> tuple[tuple[float, ...], ...]:
        """Count observed dependent output bits per input flip, for every round.

        EXAMPLES::

            >>> AvalancheResult("demo", "state", 2, 0, ((0.0, 0.5),)).dependence()
            ((1.0,),)
        """
        return tuple(tuple(sum(row) for row in matrix) for matrix in self.vectors("dependence"))

    def weight(self) -> tuple[tuple[float, ...], ...]:
        """Return expected output-difference Hamming weights per round/input flip.

        EXAMPLES::

            >>> AvalancheResult("demo", "state", 2, 0, ((0.0, 0.5),)).weight()
            ((0.5,),)
        """
        return tuple(tuple(sum(row) for row in matrix) for matrix in self.vectors())

    def entropy(self) -> tuple[tuple[float, ...], ...]:
        """Sum binary output-bit entropies per round/input flip, in bits.

        EXAMPLES::

            >>> AvalancheResult("demo", "state", 2, 0, ((0.0, 0.5),)).entropy()
            ((1.0,),)
        """
        return tuple(tuple(sum(row) for row in matrix) for matrix in self.vectors("entropy"))

    def check_criteria(
        self,
        *,
        dependence_threshold: float = 0.0,
        weight_threshold: float = 0.01,
        entropy_threshold: float = 0.01,
    ) -> tuple[dict[str, int | float | bool | None], ...]:
        """Check full diffusion, avalanche and strict avalanche for every round.

        Tolerances are absolute output-bit counts (entropy uses bits). Every
        input flip must pass. Decisions concern finite-sample estimates only.

        EXAMPLES::

            >>> result = AvalancheResult("demo", "state", 2, 0, ((0.5, 0.5),))
            >>> result.check_criteria()[0]["strict_avalanche"]
            True
        """
        for value in (dependence_threshold, weight_threshold, entropy_threshold):
            if isinstance(value, bool) or not isfinite(value) or value < 0:
                raise ValueError("criterion tolerances must be finite and nonnegative")
        return tuple(
            {
                "round": number,
                "full_diffusion": all(
                    value >= len(matrix[0]) - dependence_threshold for value in dependence
                ),
                "avalanche": all(
                    abs(value - len(matrix[0]) / 2) <= weight_threshold for value in weight
                ),
                "strict_avalanche": all(
                    value >= len(matrix[0]) - entropy_threshold for value in entropy
                ),
                "dependence_threshold": dependence_threshold,
                "weight_threshold": weight_threshold,
                "entropy_threshold": entropy_threshold,
            }
            for (number, matrix), dependence, weight, entropy in zip(
                _round_data(self), self.dependence(), self.weight(), self.entropy(), strict=True
            )
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
    input_name: str | None = None,
    number_of_samples: int = 1000,
    *,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
    metric: str = "probability",
    threshold: float | None = None,
    confidence: float = 0.95,
    engine: str = "numpy",
) -> AvalancheResult:
    """Estimate a primitive's strict-avalanche probability matrix.

    By default the first declared input is varied, using 1,000 samples and
    seed zero. For each sampled input, the function evaluates a baseline and then flips
    each bit of ``input_name`` independently.  Randomness is reproducible and
    NumPy evaluates samples in parallel by default (``analysis`` extra).
    ``engine="scalar"`` selects the dependency-free reference evaluator.
    Other component types use scalar handlers per lane within NumPy execution;
    ``method`` reports hybrid execution when applicable. Published graph round
    boundaries supply intermediate outputs.
    Reports default to a Hoeffding/union-bound SAC compatibility check at
    ``confidence=0.95``, covering all retained rounds and bit pairs. The band
    depends on sample count. Passing does not establish equality with 0.5.
    ``threshold`` overrides this with a fixed per-metric tolerance.
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
    _validate_reporting(threshold, confidence)
    if input_name is None:
        input_name = next(iter(primitive.graph.input_arrays))
    if engine not in {"numpy", "scalar"}:
        raise ValueError("engine must be numpy or scalar")
    if not isinstance(number_of_samples, int) or isinstance(number_of_samples, bool):
        raise TypeError("number_of_samples must be an integer")
    if number_of_samples <= 0:
        raise ValueError("number_of_samples must be positive")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")
    fixed = dict(fixed_inputs or {})
    if set(fixed) - set(primitive.graph.input_arrays):
        raise ValueError("unknown fixed inputs")
    for name, value in fixed.items():
        width = packed_bit_width(primitive, name)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << width):
            raise ValueError(f"invalid packed value for {name}")
    random = Random(seed)
    input_width = packed_bit_width(primitive, input_name)
    packed_bit_width(primitive)  # Reject non-binary output encodings.
    sample_inputs = [
        {
            name: fixed[name]
            if name in fixed
            else random.getrandbits(packed_bit_width(primitive, name))
            for name in primitive.graph.input_arrays
        }
        for _ in range(number_of_samples)
    ]
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

    method = "scalar_paired_evaluation"
    if engine == "numpy":
        try:
            import numpy as np
        except ImportError as error:
            raise ImportError(
                "NumPy avalanche evaluation requires: pip install 'claasp[analysis]' (or use engine='scalar')"
            ) from error
        from claasp.representations.execution._numpy import _evaluate_samples

        method = "numpy_paired_evaluation"
        # Bound trace memory independently of the requested sample budget.
        for start in range(0, number_of_samples, 256):
            batch = sample_inputs[start : start + 256]
            inputs = {name: [item[name] for item in batch] for name in primitive.graph.input_arrays}
            baseline, hybrid = _evaluate_samples(primitive, inputs, [items for _, items in outputs])
            if hybrid:
                method = "numpy_hybrid_paired_evaluation"
            for input_bit in range(input_width):
                changed = dict(inputs)
                changed[input_name] = [
                    value ^ (1 << (input_width - input_bit - 1)) for value in inputs[input_name]
                ]
                measured, _ = _evaluate_samples(primitive, changed, [items for _, items in outputs])
                for index, (left, right) in enumerate(zip(baseline, measured, strict=True)):
                    totals = np.sum(left ^ right, axis=1)
                    for bit, count in enumerate(totals):
                        counts[index][input_bit][bit] += int(count)
    else:
        for scalar_inputs in sample_inputs:
            baseline = packed_outputs(primitive.evaluate_with_trace(scalar_inputs))
            for input_bit in range(input_width):
                changed_sample = dict(scalar_inputs)
                changed_sample[input_name] ^= 1 << (input_width - input_bit - 1)
                changed_outputs = packed_outputs(primitive.evaluate_with_trace(changed_sample))
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
        method=method,
        round_probabilities=matrices if final_number else (),
        round_numbers=tuple(number for number, _ in outputs) if final_number else (),
        metric=metric,
        threshold=threshold,
        confidence=confidence,
    )


def _validate_metric(metric: str) -> str:
    if metric not in {"probability", "entropy", "weight", "dependence"}:
        raise ValueError("metric must be probability, dependence, entropy, or weight")
    return metric


def _metric_matrix(matrix, metric):
    _validate_metric(metric)
    if metric == "dependence":
        return tuple(tuple(float(value > 0) for value in row) for row in matrix)
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


def _validate_reporting(threshold, confidence):
    if threshold is not None and (
        isinstance(threshold, bool) or not isfinite(threshold) or not 0 <= threshold <= 1
    ):
        raise ValueError("threshold must be None or a finite tolerance between zero and one")
    if isinstance(confidence, bool) or not isfinite(confidence) or not 0 < confidence < 1:
        raise ValueError("confidence must be finite and strictly between zero and one")


def _comparison_count(result):
    return sum(len(matrix) * len(matrix[0]) for _, matrix in _round_data(result))


def _sampling_radius(result):
    # Hoeffding per Bernoulli mean, then a union bound over all retained
    # round/input/output pairs. Pairs may be dependent; samples must be iid.
    return sqrt(
        log(2 * _comparison_count(result) / (1 - result.confidence)) / (2 * result.sample_count)
    )


def _report_bounds(result, metric):
    if result.threshold is not None:
        return _criterion_bounds(metric, result.threshold)
    _validate_metric(metric)
    if metric == "dependence":
        return 1.0, 1.0
    radius = min(0.5, _sampling_radius(result))
    if metric == "entropy":
        probability = 0.5 - radius
        lower = _metric_matrix(((probability,),), "entropy")[0][0]
        return lower, 1.0
    return 0.5 - radius, 0.5 + radius


def _report_label(result, metric):
    if result.threshold is not None:
        return "Tolerance check"
    return "Observed diffusion" if metric == "dependence" else "SAC check"


def _report_status(result, metric, satisfied):
    if result.threshold is not None:
        return "met" if satisfied else "not met"
    if metric == "dependence":
        return "all bits observed" if satisfied else "missing flips"
    if _sampling_radius(result) >= 0.5:
        return "inconclusive"
    return "consistent" if satisfied else "deviation detected"


def _criterion_bounds(metric, threshold):
    _validate_metric(metric)
    target = 1.0 if metric in {"entropy", "dependence"} else 0.5
    return max(0.0, target - threshold), min(1.0, target + threshold)


def _round_statistics(result, metric):
    lower, upper = _report_bounds(result, metric)
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
