"""Sampled continuous avalanche factors using precision-local graph execution."""

from __future__ import annotations

import pathlib
from dataclasses import dataclass
from importlib import import_module
from math import isclose, isfinite, prod, sqrt
from typing import TYPE_CHECKING, TextIO

from claasp.analysis.datasets import packed_bit_width
from claasp.graph import Primitive

if TYPE_CHECKING:
    from claasp.drivers.renderers.presentation import FigureArtifact


@dataclass(frozen=True, slots=True)
class ContinuousDiffusionResult:
    """Per-round CAF samples, output-coordinate vectors, and reproducibility settings.

    ``vectors`` contains mean signed-distance contributions in [0, 2], with
    each vector averaging to its round CAF. These are heuristic model results.

    EXAMPLES::

        >>> result = ContinuousDiffusionResult("identity", "state", 0, 0.001, 80, (1,), ((0.0, 0.0),))
        >>> result.factors
        (0.0,)
    """

    primitive_family: str
    input_name: str
    seed: int
    lambda_value: float
    precision: int
    round_numbers: tuple[int, ...]
    samples: tuple[tuple[float, ...], ...]
    method: str = "boolean_neighborhood"
    claim_kind: str = "heuristic"
    vectors: tuple[tuple[float, ...], ...] = ()
    sampling_engine: str = "numpy_PCG64"

    def __post_init__(self) -> None:
        if not self.samples or any(not row for row in self.samples):
            raise ValueError("continuous diffusion samples must be nonempty")
        if (
            len(self.samples) != len(self.round_numbers)
            or len({len(row) for row in self.samples}) != 1
        ):
            raise ValueError("round numbers and equal-sized sample rows must match")
        if tuple(sorted(set(self.round_numbers))) != self.round_numbers:
            raise ValueError("round numbers must be unique and increasing")
        if any(not isfinite(value) or not 0 <= value <= 2 for row in self.samples for value in row):
            raise ValueError("CAF samples must be finite and in [0, 2]")
        if self.claim_kind != "heuristic":
            raise ValueError("continuous diffusion results must remain heuristic")

        if self.vectors:
            if len(self.vectors) != len(self.round_numbers) or any(not row for row in self.vectors):
                raise ValueError("CAF vectors must match the retained rounds and be nonempty")
            if any(
                not isfinite(value) or not 0 <= value <= 2 for row in self.vectors for value in row
            ):
                raise ValueError("CAF vector contributions must be finite and in [0, 2]")
            if any(
                not isclose(sum(vector) / len(vector), factor, abs_tol=1e-12)
                for vector, factor in zip(self.vectors, self.factors, strict=True)
            ):
                raise ValueError("CAF vector means must match round CAF values")

    @property
    def factors(self) -> tuple[float, ...]:
        """Return the mean normalized signed distance for each round.

        EXAMPLES::

            >>> ContinuousDiffusionResult("identity", "state", 0, .001, 80, (1,), ((0., 1.),)).factors
            (0.5,)
        """
        return tuple(sum(row) / len(row) for row in self.samples)

    def to_terminal(self, *, details: bool = False, file: TextIO | None = None) -> None:
        """Print settings and the round-by-round CAF table.

        ``details=True`` includes each round's per-output contribution vector.

        EXAMPLES::

            >>> from io import StringIO
            >>> output = StringIO()
            >>> result = ContinuousDiffusionResult("identity", "state", 0, .001, 80, (1,), ((0.,),))
            >>> result.to_terminal(file=output)
            >>> "CAF" in output.getvalue()
            True
        """
        from claasp.presentation._terminal import to_terminal
        from claasp.presentation.adapters import _continuous_diffusion_section

        to_terminal(_continuous_diffusion_section(self, details=details), file=file)

    def plot(
        self,
        *,
        view: str = "summary",
        style: str = "planes",
        show: bool = True,
        save_to: str | pathlib.Path | None = None,
    ) -> FigureArtifact:
        """Plot retained CAF means or per-output-coordinate contributions.

        ``view`` is ``"summary"`` (default), ``"heatmap"`` or ``"3d"``.
        The 3D ``style`` is ``"planes"`` or ``"dots"``. Vector values are
        signed-distance contributions in [0, 2], rather than probabilities.

        EXAMPLES::

            >>> callable(ContinuousDiffusionResult.plot)
            True
        """
        from claasp.drivers.renderers.presentation import _plot_continuous_diffusion

        return _plot_continuous_diffusion(self, view=view, style=style, show=show, save_to=save_to)


def _near_pair(random, context, width, distance):
    # A uniform displacement in the ball, accepted in proportion to the
    # intersection volume, samples uniform ordered pairs conditioned on distance.
    for _ in range(100000):
        direction = random.normal(size=width).tolist()
        norm = sqrt(sum(value * value for value in direction))
        if norm == 0:
            continue
        radius = distance * random.random() ** (1 / width)
        displacement = [context.mpf(value / norm * radius) for value in direction]
        overlap = prod(float(1 - abs(value) / 2) for value in displacement)
        if random.random() > overlap:
            continue
        left, right = [], []
        for delta in displacement:
            lower, upper = max(-1, -1 - delta), min(1, 1 - delta)
            value = lower + context.mpf(random.random()) * (upper - lower)
            left.append(value)
            right.append(value + delta)
        return tuple(left), tuple(right)
    raise ValueError("pair sampling failed; use a smaller lambda_value")


def _boolean_pair(random, context, width, distance):
    left = tuple(context.mpf(2 * bit - 1) for bit in random.integers(0, 2, size=width).tolist())
    right = list(left)
    bit = int(random.integers(width))
    right[bit] *= 1 - context.mpf(random.random()) * distance
    return left, tuple(right)


def continuous_diffusion(
    primitive: Primitive,
    input_name: str | None = None,
    number_of_samples: int = 16,
    *,
    lambda_value: float = 0.001,
    seed: int = 0,
    precision: int = 80,
    sampling: str = "boolean_neighborhood",
) -> ContinuousDiffusionResult:
    """Estimate the continuous avalanche factor at every published round.

    The default perturbs one randomly selected Boolean input coordinate inward,
    staying within [-1, 1]. ``sampling="uniform_near_pairs"`` instead samples
    uniform ordered continuous pairs conditional on Euclidean distance at most
    lambda_value. Other inputs are independent Boolean vectors shared by each
    pair. Each round's signed output distance is divided by its output width.
    Sampling uses a local NumPy Generator; its engine is retained in the result.
    Precision is decimal digits and is local to this experiment.

    EXAMPLES::

        >>> try:
        ...     continuous_diffusion()
        ... except TypeError:
        ...     print("primitive required")
        primitive required
    """
    if sampling not in {"boolean_neighborhood", "uniform_near_pairs"}:
        raise ValueError("sampling must be boolean_neighborhood or uniform_near_pairs")
    if input_name is None:
        input_name = next(iter(primitive.graph.input_arrays))
    width = packed_bit_width(primitive, input_name)
    packed_bit_width(primitive)
    for name, value, minimum in (
        ("number_of_samples", number_of_samples, 1),
        ("precision", precision, 20),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise ValueError(f"{name} must be an integer >= {minimum}")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer")
    if isinstance(lambda_value, bool) or not isfinite(lambda_value) or not 0 < lambda_value <= 1:
        raise ValueError("lambda_value must be finite and in (0, 1]")
    try:
        context = import_module("mpmath").mp.clone()
        numpy = import_module("numpy")
    except ImportError as error:
        raise ImportError(
            "Continuous diffusion requires: pip install 'claasp[analysis]'"
        ) from error
    context.dps = precision
    random = numpy.random.default_rng(numpy.random.PCG64(seed))
    final = primitive.details().number_of_rounds
    setup = max(0, len(primitive.graph.rounds) - final)
    outputs = [
        (number + 1 - setup, selections)
        for number, selections in primitive.graph.round_output_boundaries
        if number + 1 > setup
    ]
    final_output = primitive.graph.output
    assert final_output is not None
    if outputs and outputs[-1][0] == final:
        outputs[-1] = (final, (final_output,))
    else:
        outputs.append((final, (final_output,)))
    scores: list[list[float]] = [[] for _ in outputs]
    totals: list[list[float]] = [[] for _ in outputs]
    from claasp.representations.execution._continuous_precision import _continuous_outputs

    for _ in range(number_of_samples):
        pair = _boolean_pair if sampling == "boolean_neighborhood" else _near_pair
        left, right = pair(random, context, width, lambda_value)
        inputs = {
            name: tuple(
                context.mpf(2 * bit - 1)
                for bit in random.integers(0, 2, size=packed_bit_width(primitive, name)).tolist()
            )
            for name in primitive.graph.input_arrays
        }
        inputs[input_name] = left
        first = _continuous_outputs(primitive, inputs, [selections for _, selections in outputs])
        inputs[input_name] = right
        second = _continuous_outputs(primitive, inputs, [selections for _, selections in outputs])
        for row, total, x, y in zip(scores, totals, first, second, strict=True):
            contributions = [
                float(abs(context.sign(a) - context.sign(b))) for a, b in zip(x, y, strict=True)
            ]
            if not total:
                total.extend([0.0] * len(contributions))
            for bit, contribution in enumerate(contributions):
                total[bit] += contribution
            row.append(sum(contributions) / len(contributions))
    return ContinuousDiffusionResult(
        primitive.family_name,
        input_name,
        seed,
        lambda_value,
        precision,
        tuple(number for number, _ in outputs),
        tuple(tuple(row) for row in scores),
        method=sampling,
        sampling_engine=f"numpy_{type(random.bit_generator).__name__}",
        vectors=tuple(tuple(value / number_of_samples for value in row) for row in totals),
    )
