"""Circle differentials and concrete trails on the shared primitive evaluator.

Exact search enumerates actual input pairs for a fixed key and tweak. It does
not replace their distribution with a product of independently computed DDTs.
Sampling verifies a differential or trail selected before the experiment;
search optimality is claimed only after complete bounded enumeration.
"""

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
from math import log, sqrt
from pathlib import Path
from random import Random
from typing import TYPE_CHECKING, TextIO

from claasp.analysis._circle import _BinaryCircleAnalysis
from claasp.graph.unit_array import Selection
from claasp.semantics.cryptanalysis._circle_algebra import integer
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.semantics.cryptanalysis.circle_differential import CircleDifferentialTransitionSemantics

if TYPE_CHECKING:
    from claasp.drivers.renderers.presentation import FigureArtifact


def _positive(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


def _sampling(samples: int, seed: int, confidence: float) -> None:
    _positive(samples, "samples")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if not 0 < confidence < 1:
        raise ValueError("confidence must lie strictly between zero and one")


@dataclass(frozen=True, slots=True)
class CircleDifferentialProbability:
    """Retained fixed-input probability evidence, exact or uniformly sampled.

    ``trials`` counts ordered pairs (x, x circle a), with x uniform over the
    varying input. Exact enumeration includes every x once; sampling is with
    replacement. Confidence intervals concern a prespecified differential.
    Bases and fixed inputs are retained so the event is unambiguous.

    EXAMPLES::

        >>> from claasp.primitives import BitVectorSBox
        >>> r = BitVectorSBox(2, (0, 1, 3, 2)).analysis.circle_differential(input_name='input').probability(1, 1)
        >>> r.probability, r.hits, r.trials, r.complete
        (Fraction(1, 1), 4, 4, True)
        >>> r.lower, r.upper
        (1.0, 1.0)
    """

    input_difference: int
    output_difference: int
    hits: int
    trials: int
    complete: bool
    input_basis: CircleBasis
    output_basis: CircleBasis
    input_name: str
    primitive_name: str
    fixed_inputs: tuple[tuple[str, int], ...] = ()
    seed: int | None = None
    confidence: float | None = None
    event: str = "endpoint"

    def __post_init__(self) -> None:
        if self.event not in {"endpoint", "concrete_trail"}:
            raise ValueError("event must identify an endpoint or concrete_trail")
        integer(self.input_difference, self.input_basis.width, "input difference")
        integer(self.output_difference, self.output_basis.width, "output difference")
        _positive(self.trials, "trials")
        if (
            isinstance(self.hits, bool)
            or not isinstance(self.hits, int)
            or not 0 <= self.hits <= self.trials
        ):
            raise ValueError("hits must be an integer between zero and trials")
        if self.complete:
            if (
                self.trials != 1 << self.input_basis.width
                or self.seed is not None
                or self.confidence is not None
            ):
                raise ValueError(
                    "exact evidence must cover the domain and have no sampling parameters"
                )
        else:
            if self.seed is None or self.confidence is None:
                raise ValueError("sampled evidence requires seed and confidence")
            _sampling(self.trials, self.seed, self.confidence)
        object.__setattr__(self, "fixed_inputs", tuple(sorted(self.fixed_inputs)))

    @property
    def probability(self) -> Fraction:
        """Exact probability, or the empirical hit frequency when sampled.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').probability(1, 1).probability
            Fraction(1, 1)
        """
        return Fraction(self.hits, self.trials)

    @property
    def standard_error(self) -> float:
        """Binomial plug-in standard error; zero for complete enumeration.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').probability(1, 1).standard_error
            0.0
        """
        p = float(self.probability)
        return 0.0 if self.complete else sqrt(p * (1 - p) / self.trials)

    def _radius(self) -> float:
        return (
            0.0
            if self.confidence is None
            else sqrt(log(2 / (1 - self.confidence)) / (2 * self.trials))
        )

    @property
    def lower(self) -> float:
        """Lower Hoeffding confidence bound, or the exact probability.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').probability(1, 1).lower
            1.0
        """
        return max(0.0, float(self.probability) - self._radius())

    @property
    def upper(self) -> float:
        """Upper Hoeffding confidence bound, including when no hits occur.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').estimate_probability(1, 0, samples=8).upper > 0
            True
        """
        return min(1.0, float(self.probability) + self._radius())

    def to_terminal(self, *, file: TextIO | None = None) -> None:
        """Print retained probability evidence without evaluating the primitive again.

        EXAMPLES::

            >>> from io import StringIO
            >>> from claasp.primitives import BitVectorSBox
            >>> r = BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').probability(1, 1)
            >>> output = StringIO(); r.to_terminal(file=output)
            >>> 'Probability' in output.getvalue()
            True
        """
        from claasp.presentation._circle_differential import probability_section
        from claasp.presentation._terminal import to_terminal

        to_terminal(probability_section(self), file=file)

    def plot(self, *, show: bool = True, save_to: str | Path | None = None) -> "FigureArtifact":
        """Plot retained hit/miss probabilities, with intervals when sampled.

        Requires the optional ``presentation`` extra. Analysis is not repeated.

        EXAMPLES::

            >>> callable(CircleDifferentialProbability.plot)
            True
        """
        from claasp.drivers.renderers.presentation import _plot_circle_differential

        return _plot_circle_differential(self, show=show, save_to=save_to)


@dataclass(frozen=True, slots=True)
class CircleDifferentialTrail:
    """A concrete boundary-difference event measured on actual executions.

    Prefix counts retain how many initial inputs satisfy every boundary up to
    that point. Their ratios are *conditional* probabilities under this fixed
    key and input distribution, not independently computed local DDT entries.
    ``searched`` certifies an exhaustive best-trail search for the supplied
    input difference and optional endpoint constraint only.

    EXAMPLES::

        >>> from claasp.primitives import BitVectorSBox
        >>> r = BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').best_trail(1)
        >>> r.differences, r.probability, r.searched
        ((1, 1), Fraction(1, 1), True)
    """

    differences: tuple[int, ...]
    boundary_labels: tuple[str, ...]
    bases: tuple[CircleBasis, ...]
    observations: tuple[tuple[Selection, ...], ...]
    prefix_counts: tuple[int, ...]
    evidence: CircleDifferentialProbability
    witness: tuple[int, int] | None
    searched: bool = False
    search_output_difference: int | None = None

    def __post_init__(self) -> None:
        for name in ("differences", "boundary_labels", "bases", "prefix_counts"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "observations", tuple(tuple(group) for group in self.observations))
        n = len(self.differences)
        if n < 2 or any(
            len(getattr(self, name)) != n
            for name in ("boundary_labels", "bases", "observations", "prefix_counts")
        ):
            raise ValueError(
                "a trail requires matching differences, bases, labels and prefix counts"
            )
        for value, basis in zip(self.differences, self.bases):
            integer(value, basis.width, "boundary difference")
        if any(
            sum(selection.array_type.encoded_bit_size or 0 for selection in group) != basis.width
            for group, basis in zip(self.observations, self.bases)
        ):
            raise ValueError("observations must match their declared circle widths")
        if self.evidence.event != "concrete_trail":
            raise ValueError("trail evidence must identify the concrete trail event")
        if any(
            isinstance(c, bool) or not isinstance(c, int) or c < 0 for c in self.prefix_counts
        ) or any(a < b for a, b in zip(self.prefix_counts, self.prefix_counts[1:])):
            raise ValueError("prefix counts must be nonnegative nonincreasing integers")
        if (self.prefix_counts[0], self.prefix_counts[-1]) != (
            self.evidence.trials,
            self.evidence.hits,
        ):
            raise ValueError("prefix counts must agree with the retained evidence")
        if (self.differences[0], self.differences[-1], self.bases[0], self.bases[-1]) != (
            self.evidence.input_difference,
            self.evidence.output_difference,
            self.evidence.input_basis,
            self.evidence.output_basis,
        ):
            raise ValueError("trail boundaries must agree with the retained evidence")
        if self.searched and not self.evidence.complete:
            raise ValueError("search optimality requires complete enumeration")
        if self.search_output_difference is not None and (
            not self.searched or self.search_output_difference != self.differences[-1]
        ):
            raise ValueError("search endpoint constraint must match the searched trail")
        if bool(self.evidence.hits) != (self.witness is not None):
            raise ValueError("a nonempty concrete trail requires a witness")
        if self.witness is not None:
            x, y = self.witness
            if self.bases[0].circle(x, y) != self.differences[0]:
                raise ValueError("witness has the wrong input difference")

    @property
    def probability(self) -> Fraction:
        """Actual trail-event probability, or its sampled frequency.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').best_trail(1).probability
            Fraction(1, 1)
        """
        return self.evidence.probability

    @property
    def conditional_probabilities(self) -> tuple[Fraction | None, ...]:
        """Prefix-conditioned transition probabilities; None after an empty prefix.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').best_trail(1).conditional_probabilities
            (Fraction(1, 1),)
        """
        return tuple(
            Fraction(b, a) if a else None
            for a, b in zip(self.prefix_counts, self.prefix_counts[1:])
        )

    def to_terminal(self, *, details: bool = False, file: TextIO | None = None) -> None:
        """Print boundary differences and conditional/cumulative probabilities.

        EXAMPLES::

            >>> from io import StringIO
            >>> from claasp.primitives import BitVectorSBox
            >>> r = BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input').best_trail(1)
            >>> output = StringIO(); r.to_terminal(file=output)
            >>> 'Difference' in output.getvalue()
            True
        """
        from claasp.presentation._circle_differential import trail_section
        from claasp.presentation._terminal import to_terminal

        to_terminal(trail_section(self, details=details), file=file)

    def plot(self, *, show: bool = True, save_to: str | Path | None = None) -> "FigureArtifact":
        """Plot conditional and cumulative weights using retained prefix counts.

        Requires the optional ``presentation`` extra. Zero-probability events
        are refused because their logarithmic weights are infinite.

        EXAMPLES::

            >>> callable(CircleDifferentialTrail.plot)
            True
        """
        from claasp.drivers.renderers.presentation import _plot_circle_differential_trail

        return _plot_circle_differential_trail(self, show=show, save_to=save_to)


@dataclass(frozen=True)
class _Boundary:
    label: str
    selections: tuple[Selection, ...]
    basis: CircleBasis


class CircleDifferentialAnalysis(_BinaryCircleAnalysis):
    """Measure circle differences through any concretely evaluable binary graph.

    Supply ``bibrace`` to tile both boundaries, or explicit ``input_basis`` and
    ``output_basis`` for different cell layouts. Omitting them selects XOR.
    All other inputs, including keys and tweaks, must be fixed explicitly.
    Exact methods refuse excessive domains before evaluating the primitive.
    Trail methods use published round outputs, or explicit selections, and
    reuse the standard evaluator's traces and shared graph wiring.

    EXAMPLES::

        >>> from claasp.primitives import BitVectorSBox
        >>> a = BitVectorSBox(2, (0, 1, 3, 2)).analysis.circle_differential(input_name='input')
        >>> a.probability(1, 1).probability
        Fraction(1, 1)
        >>> a.best_differential().input_difference
        1
        >>> a.best_trail(1).differences
        (1, 1)
    """

    _analysis_name = "circle-differential"

    def _size(self, maximum_inputs: int) -> int:
        _positive(maximum_inputs, "maximum_inputs")
        size = 1 << self.input_basis.width
        if size > maximum_inputs:
            raise ValueError("exact enumeration exceeds maximum_inputs; use sampling")
        return size

    def _evidence(
        self,
        a: int,
        b: int,
        hits: int,
        trials: int,
        fixed: dict[str, int],
        *,
        seed: int | None = None,
        confidence: float | None = None,
        event: str = "endpoint",
    ) -> CircleDifferentialProbability:
        return CircleDifferentialProbability(
            a,
            b,
            hits,
            trials,
            seed is None,
            self.input_basis,
            self.output_basis,
            self.input_name,
            self.primitive.family_name,
            tuple(sorted(fixed.items())),
            seed,
            confidence,
            event,
        )

    def _difference(self, x: int, a: int, fixed: dict[str, int]) -> int:
        other = self.input_basis.circle(x, a)
        return self.output_basis.circle(self._evaluate(x, fixed), self._evaluate(other, fixed))

    def probability(
        self,
        input_difference: int,
        output_difference: int,
        *,
        fixed_inputs: Mapping[str, int] | None = None,
        maximum_inputs: int = 1 << 16,
    ) -> CircleDifferentialProbability:
        """Enumerate the actual endpoint probability at a fixed key and tweak.

        Both differences are original packed elements, not theta coordinates.
        Zero differences and nonpermutation outputs are allowed.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (0, 0)).analysis.circle_differential(input_name='input')
            >>> a.probability(1, 0).probability
            Fraction(1, 1)
        """
        integer(input_difference, self.input_basis.width, "input difference")
        integer(output_difference, self.output_basis.width, "output difference")
        size = self._size(maximum_inputs)
        fixed = self._fixed(fixed_inputs)
        hits = sum(
            self._difference(x, input_difference, fixed) == output_difference for x in range(size)
        )
        return self._evidence(input_difference, output_difference, hits, size, fixed)

    def estimate_probability(
        self,
        input_difference: int,
        output_difference: int,
        *,
        fixed_inputs: Mapping[str, int] | None = None,
        samples: int = 4096,
        seed: int = 0,
        confidence: float = 0.95,
    ) -> CircleDifferentialProbability:
        """Sample uniform ordered pairs with a distribution-free Hoeffding interval.

        Select the differential before sampling. Zero observed hits do not
        prove probability zero. No best-of-sample search claim is made.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input')
            >>> r = a.estimate_probability(1, 1, samples=32, seed=7)
            >>> r.probability, r.complete, r.lower < 1
            (Fraction(1, 1), False, True)
        """
        integer(input_difference, self.input_basis.width, "input difference")
        integer(output_difference, self.output_basis.width, "output difference")
        _sampling(samples, seed, confidence)
        fixed = self._fixed(fixed_inputs)
        rng = Random(seed)
        hits = sum(
            self._difference(rng.getrandbits(self.input_basis.width), input_difference, fixed)
            == output_difference
            for _ in range(samples)
        )
        return self._evidence(
            input_difference,
            output_difference,
            hits,
            samples,
            fixed,
            seed=seed,
            confidence=confidence,
        )

    def lookup_semantics(
        self, *, fixed_inputs: Mapping[str, int] | None = None, maximum_inputs: int = 1 << 16
    ) -> CircleDifferentialTransitionSemantics:
        """Build exact local transitions from the actual bounded primitive graph.

        All arithmetic, key additions and diffusion components are evaluated.
        DDT construction reuses the existing XOR transition semantics.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (1, 0)).analysis.circle_differential(input_name='input')
            >>> a.lookup_semantics().difference_distribution_table()
            ((2, 0), (0, 2))
        """
        size = self._size(maximum_inputs)
        fixed = self._fixed(fixed_inputs)
        return CircleDifferentialTransitionSemantics(
            self.input_basis,
            self.output_basis,
            tuple(self._evaluate(x, fixed) for x in range(size)),
            maximum_inputs,
        )

    def best_differential(
        self, *, fixed_inputs: Mapping[str, int] | None = None, maximum_entries: int = 1 << 16
    ) -> CircleDifferentialProbability:
        """Find the best endpoint differential over all nonzero input differences.

        Output difference zero is allowed (important for nonpermutations).
        Ties use the smallest input, then output difference. This is a full
        endpoint search, not a local-probability characteristic search.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (0, 0)).analysis.circle_differential(input_name='input')
            >>> r = a.best_differential()
            >>> r.input_difference, r.output_difference, r.probability
            (1, 0, Fraction(1, 1))
        """
        n, m = self.input_basis.width, self.output_basis.width
        _positive(maximum_entries, "maximum_entries")
        if max(1 << (n + m), 1 << (2 * n)) > maximum_entries:
            raise ValueError("endpoint DDT exceeds maximum_entries")
        fixed = self._fixed(fixed_inputs)
        semantics = self.lookup_semantics(fixed_inputs=fixed, maximum_inputs=1 << n)
        ddt = semantics.difference_distribution_table(maximum_entries=maximum_entries)
        a, b = max(
            ((a, b) for a in range(1, 1 << n) for b in range(1 << m)),
            key=lambda pair: ddt[pair[0]][pair[1]],
        )
        return self._evidence(a, b, ddt[a][b], 1 << n, fixed)

    def _boundaries(
        self,
        boundaries: tuple[Selection, ...] | None,
        boundary_bases: tuple[CircleBasis, ...] | None,
    ) -> tuple[_Boundary, ...]:
        graph = self.primitive.graph
        assert graph.output is not None
        if boundaries is None:
            selected = [
                (f"round {number + 1}", selections)
                for number, selections in graph.round_output_boundaries
            ]
            output_sources = graph.selection_bit_sources(graph.output)
            if (
                selected
                and tuple(
                    source
                    for selection in selected[-1][1]
                    for source in graph.selection_bit_sources(selection)
                )
                == output_sources
            ):
                selected.pop()
        else:
            selected = [
                (f"boundary {i + 1}", (selection,)) for i, selection in enumerate(boundaries)
            ]
        if boundary_bases is not None and len(boundary_bases) != len(selected):
            raise ValueError("one boundary basis is required per intermediate boundary")
        result = []
        for i, (label, selections) in enumerate(selected):
            width = sum(len(graph.selection_bit_sources(selection)) for selection in selections)
            if boundary_bases is not None:
                basis = boundary_bases[i]
            elif all(not cell.forms for cell in self.input_basis.cells):
                basis = CircleBasis((BinaryBibrace(width),))
            elif (
                len(set(self.input_basis.cells)) == 1
                and width % self.input_basis.cells[0].width == 0
            ):
                cell = self.input_basis.cells[0]
                basis = CircleBasis((cell,) * (width // cell.width))
            elif width == self.input_basis.width:
                basis = self.input_basis
            else:
                raise ValueError("supply boundary_bases for the intermediate cell layout")
            if basis.width != width:
                raise ValueError("boundary basis must match the selected packed width")
            result.append(_Boundary(label, selections, basis))
        return (*result, _Boundary("output", (graph.output,), self.output_basis))

    def _path(
        self, x: int, a: int, fixed: dict[str, int], boundaries: tuple[_Boundary, ...]
    ) -> tuple[int, ...]:
        other = self.input_basis.circle(x, a)
        left = self.primitive.evaluate_with_trace({**fixed, self.input_name: x})
        right = self.primitive.evaluate_with_trace({**fixed, self.input_name: other})

        def packed(trace, selections):
            value = 0
            for selection in selections:
                width = selection.array_type.encoded_bit_size
                assert width is not None
                units = self.primitive.graph.resolve_selection(selection, trace.values, {})
                encoded = self.primitive._encode_boundary(units, selection.array_type)
                if not isinstance(encoded, int):
                    raise TypeError("binary boundary did not encode as an integer")
                value = (value << width) | encoded
            return value

        return (
            a,
            *(
                boundary.basis.circle(
                    packed(left, boundary.selections), packed(right, boundary.selections)
                )
                for boundary in boundaries
            ),
        )

    def _trail(
        self,
        differences: tuple[int, ...],
        boundaries: tuple[_Boundary, ...],
        counts: tuple[int, ...],
        trials: int,
        fixed: dict[str, int],
        witness: int | None,
        *,
        searched: bool = False,
        seed: int | None = None,
        confidence: float | None = None,
        search_output_difference: int | None = None,
    ) -> CircleDifferentialTrail:
        evidence = self._evidence(
            differences[0],
            differences[-1],
            counts[-1],
            trials,
            fixed,
            seed=seed,
            confidence=confidence,
            event="concrete_trail",
        )
        return CircleDifferentialTrail(
            differences,
            ("input", *(b.label for b in boundaries)),
            (self.input_basis, *(b.basis for b in boundaries)),
            (
                (self.primitive.graph.input(self.input_name).select_all(),),
                *(b.selections for b in boundaries),
            ),
            counts,
            evidence,
            None
            if witness is None
            else (witness, self.input_basis.circle(witness, differences[0])),
            searched,
            search_output_difference,
        )

    def best_trail(
        self,
        input_difference: int,
        output_difference: int | None = None,
        *,
        fixed_inputs: Mapping[str, int] | None = None,
        boundaries: tuple[Selection, ...] | None = None,
        boundary_bases: tuple[CircleBasis, ...] | None = None,
        maximum_inputs: int = 1 << 16,
    ) -> CircleDifferentialTrail | None:
        """Find the most probable concrete trail for a fixed input difference.

        Enumerates actual pairs and all observed boundary histories, using
        published round outputs by default. Custom boundaries replace the
        intermediate observations; input and final output are always retained.
        With no intermediate boundaries this searches only endpoint events.
        Ties use lexicographic difference order. An impossible constrained
        endpoint returns None. The all-zero input difference is excluded.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(2, (0, 1, 3, 2)).analysis.circle_differential(input_name='input')
            >>> a.best_trail(1).prefix_counts
            (4, 4)
            >>> a.best_trail(1, 0) is None
            True
        """
        integer(input_difference, self.input_basis.width, "input difference")
        if not input_difference:
            raise ValueError("trail search requires a nonzero input difference")
        if output_difference is not None:
            integer(output_difference, self.output_basis.width, "output difference")
        size = self._size(maximum_inputs)
        fixed = self._fixed(fixed_inputs)
        observed = self._boundaries(boundaries, boundary_bases)
        counts: Counter[tuple[int, ...]] = Counter()
        witnesses: dict[tuple[int, ...], int] = {}
        for x in range(size):
            path = self._path(x, input_difference, fixed, observed)
            counts[path] += 1
            witnesses.setdefault(path, x)
        candidates = sorted(
            path for path in counts if output_difference is None or path[-1] == output_difference
        )
        if not candidates:
            return None
        best = max(candidates, key=lambda path: counts[path])
        prefixes = tuple(
            sum(count for path, count in counts.items() if path[:i] == best[:i])
            for i in range(1, len(best) + 1)
        )
        return self._trail(
            best,
            observed,
            prefixes,
            size,
            fixed,
            witnesses[best],
            searched=True,
            search_output_difference=output_difference,
        )

    def trail_probability(
        self,
        differences: tuple[int, ...],
        *,
        fixed_inputs: Mapping[str, int] | None = None,
        boundaries: tuple[Selection, ...] | None = None,
        boundary_bases: tuple[CircleBasis, ...] | None = None,
        maximum_inputs: int = 1 << 16,
        samples: int | None = None,
        seed: int = 0,
        confidence: float = 0.95,
    ) -> CircleDifferentialTrail:
        """Validate realizability and measure a prespecified concrete trail.

        Exact enumeration proves existence or impossibility for the fixed
        inputs and declared observations. With ``samples``, zero hits only
        bound the probability; a retained witness proves existence. The final
        interval concerns the whole trail event. Prefix frequencies are not
        independent local DDT probabilities. No search is performed.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> a = BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name='input')
            >>> a.trail_probability((1, 0)).probability
            Fraction(0, 1)
            >>> a.trail_probability((1, 1), samples=8).evidence.complete
            False
        """
        observed = self._boundaries(boundaries, boundary_bases)
        differences = tuple(differences)
        bases = (self.input_basis, *(b.basis for b in observed))
        if len(differences) != len(bases):
            raise ValueError("one difference is required at every retained boundary")
        for value, basis in zip(differences, bases):
            integer(value, basis.width, "boundary difference")
        fixed = self._fixed(fixed_inputs)
        if samples is None:
            trials = self._size(maximum_inputs)
            inputs = iter(range(trials))
        else:
            _sampling(samples, seed, confidence)
            trials = samples
            rng = Random(seed)
            inputs = (rng.getrandbits(self.input_basis.width) for _ in range(samples))
        counts = [0] * len(differences)
        witness = None
        for x in inputs:
            path = self._path(x, differences[0], fixed, observed)
            matched = True
            for i, (actual, expected) in enumerate(zip(path, differences)):
                matched = matched and actual == expected
                counts[i] += int(matched)
            if matched and witness is None:
                witness = x
        return self._trail(
            differences,
            observed,
            tuple(counts),
            trials,
            fixed,
            witness,
            seed=None if samples is None else seed,
            confidence=None if samples is None else confidence,
        )


__all__ = ["CircleDifferentialAnalysis", "CircleDifferentialProbability", "CircleDifferentialTrail"]
