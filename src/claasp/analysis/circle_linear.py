"""Primitive-independent fixed-input circle-linear correlation analysis.

This facade uses the primitive's concrete evaluator, so measurement supports
binary arithmetic, unrolled feedback, and variable-control operations whenever
the evaluator supports them. It does not substitute a trail product for an
endpoint correlation. Large exact domains are rejected before evaluation.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
from math import log, sqrt
from pathlib import Path
from random import Random
from typing import TYPE_CHECKING, TextIO

from claasp.graph import Primitive
from claasp.semantics.cryptanalysis._circle_algebra import integer
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.semantics.cryptanalysis.circle_linear import CircleLookupLayer
from claasp.unit_types import BinaryExtensionField, Bit, Word

if TYPE_CHECKING:
    from claasp.drivers.renderers.presentation import FigureArtifact


@dataclass(frozen=True, slots=True)
class CircleCorrelationEstimate:
    """A seeded estimate with a distribution-free Hoeffding interval.

    The interval concerns the fixed-input endpoint correlation, not a trail
    contribution. Sampling is uniform with replacement over the varying input.

    EXAMPLES::

        >>> from claasp.primitives import BitVectorSBox
        >>> a = BitVectorSBox(2, (0, 1, 2, 3)).analysis.circle_linear(input_name='input')
        >>> r = a.estimate_correlation(1, 1, samples=100, seed=7)
        >>> r.value, r.standard_error, r.complete
        (1.0, 0.0, False)
        >>> r.lower <= 1 <= r.upper
        True
    """

    value: float
    samples: int
    seed: int
    standard_error: float
    lower: float
    upper: float
    confidence: float
    complete: bool = False

    def to_terminal(self, *, file: TextIO | None = None) -> None:
        """Print retained circle-linear evidence without repeating the analysis.

        EXAMPLES::

            >>> from io import StringIO
            >>> from claasp.analysis.circle_linear import CircleCorrelationEstimate
            >>> result = CircleCorrelationEstimate(0.5, 100, 7, 0.05, 0.2, 0.8, 0.95)
            >>> output = StringIO()
            >>> result.to_terminal(file=output)
            >>> "endpoint" in output.getvalue()
            True
        """
        from claasp.presentation._circle_linear import correlation_section as result_section
        from claasp.presentation._terminal import to_terminal

        to_terminal(result_section(self), file=file)

    def plot(self, *, show: bool = True, save_to: str | Path | None = None) -> "FigureArtifact":
        """Plot retained agreement probabilities with uncertainty when sampled.

        Requires the optional ``presentation`` extra. ``show=False`` returns
        the figure without displaying it; ``save_to`` saves it before display.
        These are endpoint probabilities, not a selected trail contribution.
        Analysis and search are never repeated.

        EXAMPLES::

            >>> from claasp.analysis.circle_linear import CircleCorrelationEstimate
            >>> result = CircleCorrelationEstimate(0.5, 100, 7, 0.05, 0.2, 0.8, 0.95)
            >>> callable(result.plot)
            True
        """
        from claasp.drivers.renderers.presentation import _plot_circle_correlation

        return _plot_circle_correlation(self, show=show, save_to=save_to)


@dataclass(frozen=True, slots=True)
class CircleApproximation:
    """An exact endpoint approximation found over a complete bounded domain.

    EXAMPLES::

        >>> a = CircleApproximation(1, 1, Fraction(-1))
        >>> a.coefficient, a.complete
        (Fraction(-1, 1), True)
    """

    input_mask: int
    output_mask: int
    coefficient: Fraction
    complete: bool = True

    def to_terminal(self, *, file: TextIO | None = None) -> None:
        """Print retained circle-linear evidence without repeating the analysis.

        EXAMPLES::

            >>> from io import StringIO
            >>> from claasp.analysis.circle_linear import CircleApproximation
            >>> result = CircleApproximation(1, 1, Fraction(1, 2))
            >>> output = StringIO()
            >>> result.to_terminal(file=output)
            >>> "endpoint" in output.getvalue()
            True
        """
        from claasp.presentation._circle_linear import correlation_section as result_section
        from claasp.presentation._terminal import to_terminal

        to_terminal(result_section(self), file=file)

    def plot(self, *, show: bool = True, save_to: str | Path | None = None) -> "FigureArtifact":
        """Plot retained agreement probabilities with uncertainty when sampled.

        Requires the optional ``presentation`` extra. ``show=False`` returns
        the figure without displaying it; ``save_to`` saves it before display.
        These are endpoint probabilities, not a selected trail contribution.
        Analysis and search are never repeated.

        EXAMPLES::

            >>> from claasp.analysis.circle_linear import CircleApproximation
            >>> result = CircleApproximation(1, 1, Fraction(1, 2))
            >>> callable(result.plot)
            True
        """
        from claasp.drivers.renderers.presentation import _plot_circle_correlation

        return _plot_circle_correlation(self, show=show, save_to=save_to)


class CircleLinearAnalysis:
    """Analyze one binary primitive using explicit input/output character bases.

    Supplying one bibrace tiles both packed boundaries with equal-sized cells.
    For different layouts supply ``input_basis`` and ``output_basis`` instead.
    With neither, ordinary XOR characters form the control case. Keys, tweaks,
    and every other nonvarying input must be supplied explicitly.

    EXAMPLES::

        >>> from claasp.primitives import BitVectorSBox
        >>> p = BitVectorSBox(2, (0, 1, 3, 2))
        >>> analysis = p.analysis.circle_linear(input_name='input')
        >>> analysis.correlation(1, 1)
        Fraction(0, 1)
        >>> analysis.best_approximation().coefficient
        Fraction(1, 1)
    """

    def __init__(
        self,
        primitive: Primitive,
        *,
        bibrace: BinaryBibrace | None = None,
        input_basis: CircleBasis | None = None,
        output_basis: CircleBasis | None = None,
        input_name: str = "plaintext",
    ) -> None:
        self.primitive = primitive
        self.input_name = input_name
        if input_name not in primitive.graph.input_arrays:
            raise ValueError("input_name must identify a declared primitive input")
        if input_name in primitive.graph.secret_inputs:
            raise ValueError("the varying input must be public; fix the secret inputs explicitly")
        if primitive.graph.output is None:
            raise ValueError("circle-linear analysis requires a declared output")
        arrays = tuple(primitive.graph.input_arrays.values()) + tuple(primitive.graph.components)
        for array in arrays:
            array_type = array.array_type if hasattr(array, "array_type") else array.output_type
            if not isinstance(array_type.unit_type, (Bit, Word, BinaryExtensionField)):
                raise NotImplementedError(
                    "binary circle-linear analysis excludes odd-prime and nonbinary units"
                )
        n = primitive.graph.input_arrays[input_name].array_type.encoded_bit_size
        m = primitive.graph.output.array_type.encoded_bit_size
        assert n is not None and m is not None
        if bibrace is not None and (input_basis is not None or output_basis is not None):
            raise ValueError("supply bibrace or explicit boundary bases, not both")
        if bibrace is not None:
            if n % bibrace.width or m % bibrace.width:
                raise ValueError("bibrace cells must tile both boundaries exactly")
            input_basis = CircleBasis((bibrace,) * (n // bibrace.width))
            output_basis = CircleBasis((bibrace,) * (m // bibrace.width))
        self.input_basis = (
            input_basis if input_basis is not None else CircleBasis((BinaryBibrace(n),))
        )
        self.output_basis = (
            output_basis if output_basis is not None else CircleBasis((BinaryBibrace(m),))
        )
        if self.input_basis.width != n or self.output_basis.width != m:
            raise ValueError("character bases must match the primitive's packed boundary widths")

    def _fixed(self, fixed_inputs: Mapping[str, int] | None) -> dict[str, int]:
        fixed = dict(fixed_inputs or {})
        expected = set(self.primitive.graph.input_arrays) - {self.input_name}
        if set(fixed) != expected:
            raise ValueError(f"fixed_inputs must contain exactly {sorted(expected)}")
        for name, value in fixed.items():
            width = self.primitive.graph.input_arrays[name].array_type.encoded_bit_size
            assert width is not None
            integer(value, width, name)
        return fixed

    def _evaluate(self, value: int, fixed: dict[str, int]) -> int:
        result = self.primitive.evaluate({**fixed, self.input_name: value})
        if not isinstance(result, int):
            raise TypeError("binary primitive evaluator did not return a packed integer")
        return result

    def correlation(
        self,
        input_mask: int,
        output_mask: int,
        *,
        fixed_inputs: Mapping[str, int] | None = None,
        maximum_inputs: int = 1 << 16,
    ) -> Fraction:
        """Compute the actual fixed-input endpoint correlation exactly.

        This enumerates the complete varying-input domain, retaining signs.
        It neither averages keys nor assumes independent round keys.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (1, 0)).analysis.circle_linear(input_name='input')
            >>> a.correlation(1, 1)
            Fraction(-1, 1)
        """
        integer(input_mask, self.input_basis.width, "input mask")
        integer(output_mask, self.output_basis.width, "output mask")
        size = 1 << self.input_basis.width
        if size > maximum_inputs:
            raise ValueError("exact correlation exceeds maximum_inputs; use estimate_correlation")
        fixed = self._fixed(fixed_inputs)
        return Fraction(
            sum(
                1
                - 2
                * (
                    self.input_basis.character(input_mask, x)
                    ^ self.output_basis.character(output_mask, self._evaluate(x, fixed))
                )
                for x in range(size)
            ),
            size,
        )

    def estimate_correlation(
        self,
        input_mask: int,
        output_mask: int,
        *,
        fixed_inputs: Mapping[str, int] | None = None,
        samples: int = 4096,
        seed: int = 0,
        confidence: float = 0.95,
    ) -> CircleCorrelationEstimate:
        """Estimate a fixed-input endpoint correlation using uniform samples.

        The reported standard error is a plug-in estimate; the Hoeffding
        interval remains conservative when every observed sign is the same.
        Resolving a bias of magnitude c generally requires order 1/c**2 samples.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (1, 0)).analysis.circle_linear(input_name='input')
            >>> a.estimate_correlation(1, 1, samples=64, seed=3).value
            -1.0
        """
        integer(input_mask, self.input_basis.width, "input mask")
        integer(output_mask, self.output_basis.width, "output mask")
        if isinstance(samples, bool) or not isinstance(samples, int) or samples < 1:
            raise ValueError("samples must be a positive integer")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        if not 0 < confidence < 1:
            raise ValueError("confidence must lie strictly between zero and one")
        fixed = self._fixed(fixed_inputs)
        rng = Random(seed)
        total = 0
        for _ in range(samples):
            x = rng.getrandbits(self.input_basis.width)
            total += 1 - 2 * (
                self.input_basis.character(input_mask, x)
                ^ self.output_basis.character(output_mask, self._evaluate(x, fixed))
            )
        mean = total / samples
        radius = sqrt(2 * log(2 / (1 - confidence)) / samples)
        return CircleCorrelationEstimate(
            mean,
            samples,
            seed,
            sqrt(max(0.0, 1 - mean * mean) / samples),
            max(-1.0, mean - radius),
            min(1.0, mean + radius),
            confidence,
        )

    def lookup_layer(
        self, *, fixed_inputs: Mapping[str, int] | None = None, maximum_inputs: int = 1 << 16
    ) -> CircleLookupLayer:
        """Turn a complete small primitive into an exact grouped local layer.

        All graph components are evaluated concretely, including arithmetic.
        Large domains are refused rather than approximated silently.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (1, 0)).analysis.circle_linear(input_name='input')
            >>> a.lookup_layer().coefficient(1, 1)
            Fraction(-1, 1)
        """
        size = 1 << self.input_basis.width
        if size > maximum_inputs:
            raise ValueError("primitive truth table exceeds maximum_inputs")
        fixed = self._fixed(fixed_inputs)
        table = tuple(self._evaluate(x, fixed) for x in range(size))
        return CircleLookupLayer(self.input_basis, self.output_basis, table, maximum_inputs)

    def best_approximation(
        self, *, fixed_inputs: Mapping[str, int] | None = None, maximum_entries: int = 1 << 16
    ) -> CircleApproximation:
        """Find the strongest nontrivial endpoint pair in a bounded full LAT.

        Both endpoint masks must be nonzero. This optimizes the complete
        endpoint correlation, not a characteristic of internal graph nodes.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (1, 0)).analysis.circle_linear(input_name='input')
            >>> a.best_approximation().coefficient
            Fraction(-1, 1)
        """
        n, m = self.input_basis.width, self.output_basis.width
        if 1 << (n + m) > maximum_entries:
            raise ValueError("endpoint LAT exceeds maximum_entries")
        fixed = self._fixed(fixed_inputs)
        table = tuple(
            self.output_basis.theta(self._evaluate(self.input_basis.theta(x), fixed))
            for x in range(1 << n)
        )
        from claasp.semantics.cryptanalysis.trails import SBoxTransitionSemantics

        walsh = SBoxTransitionSemantics(table, output_width=m).walsh_correlation_table()
        a, b = max(
            ((a, b) for a in range(1, 1 << n) for b in range(1, 1 << m)),
            key=lambda pair: abs(walsh[pair[0]][pair[1]]),
        )
        return CircleApproximation(a, b, Fraction(walsh[a][b], 1 << n))


__all__ = ["CircleApproximation", "CircleCorrelationEstimate", "CircleLinearAnalysis"]
