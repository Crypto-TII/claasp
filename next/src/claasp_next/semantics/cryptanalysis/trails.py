"""Representation-independent differential and linear trail semantics."""

from dataclasses import dataclass
from enum import Enum
from math import inf, log2
from collections import defaultdict

from claasp_next.semantics.base import XOR_DIFFERENTIAL, XOR_LINEAR


class TrailKind(str, Enum):
    """The propagation semantics represented by a trail.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import TrailKind
        >>> TrailKind.XOR_DIFFERENTIAL.semantics.name
        'xor_differential'
    """

    XOR_DIFFERENTIAL = "xor_differential"
    XOR_LINEAR = "xor_linear"

    @property
    def semantics(self):
        """Return the explicit graph semantics for this trail kind."""

        return XOR_DIFFERENTIAL if self is TrailKind.XOR_DIFFERENTIAL else XOR_LINEAR


@dataclass(frozen=True, slots=True)
class BitPattern:
    """A fixed-width difference or mask represented as an integer.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import XorDifference
        >>> XorDifference(0xA, 4).value
        10
        >>> XorDifference(4, 2)
        Traceback (most recent call last):
        ...
        ValueError: pattern value must fit its width
    """

    value: int
    width: int

    def __post_init__(self) -> None:
        if not isinstance(self.width, int) or isinstance(self.width, bool) or self.width <= 0:
            raise ValueError("pattern width must be a positive integer")
        if (
            not isinstance(self.value, int)
            or isinstance(self.value, bool)
            or not 0 <= self.value < 1 << self.width
        ):
            raise ValueError("pattern value must fit its width")


@dataclass(frozen=True, slots=True)
class XorDifference(BitPattern):
    """An XOR difference at a typed graph boundary.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import XorDifference
        >>> format(XorDifference(10, 4).value, "04b")
        '1010'
    """


@dataclass(frozen=True, slots=True)
class XorMask(BitPattern):
    """An XOR linear mask at a typed graph boundary.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import XorMask
        >>> XorMask(3, 4).width
        4
    """


@dataclass(frozen=True, slots=True)
class Transition:
    """One exact component transition and its probability/correlation weight.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import (TrailKind, Transition,
        ...     XorDifference)
        >>> transition = Transition(TrailKind.XOR_DIFFERENTIAL,
        ...     XorDifference(1, 2), XorDifference(3, 2), 1, 4)
        >>> (transition.is_possible, transition.weight)
        (True, 2.0)
    """

    kind: TrailKind
    input_pattern: BitPattern
    output_pattern: BitPattern
    numerator: int
    denominator: int
    sign: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.kind, TrailKind):
            raise TypeError("transition kind must be a TrailKind")
        expected = XorDifference if self.kind is TrailKind.XOR_DIFFERENTIAL else XorMask
        if not isinstance(self.input_pattern, expected) or not isinstance(
            self.output_pattern, expected
        ):
            raise TypeError(f"{self.kind.value} transitions require {expected.__name__} values")
        if (
            not isinstance(self.numerator, int)
            or isinstance(self.numerator, bool)
            or not isinstance(self.denominator, int)
            or isinstance(self.denominator, bool)
            or self.denominator <= 0
            or not 0 <= self.numerator <= self.denominator
        ):
            raise ValueError("transition ratio must satisfy 0 <= numerator <= denominator")
        if self.sign not in (-1, 1):
            raise ValueError("transition sign must be -1 or 1")

    @property
    def is_possible(self) -> bool:
        """Return whether the transition has nonzero probability or correlation."""
        return self.numerator != 0

    @property
    def weight(self) -> float:
        """Return ``-log2(probability)`` or ``-log2(abs(correlation))``."""

        return inf if not self.numerator else -log2(self.numerator / self.denominator)


@dataclass(frozen=True, slots=True)
class TrailStep:
    """A named component transition in a trail.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import (TrailKind, TrailStep,
        ...     Transition, XorDifference)
        >>> transition = Transition(TrailKind.XOR_DIFFERENTIAL,
        ...     XorDifference(1, 1), XorDifference(1, 1), 1, 2)
        >>> TrailStep("sbox_0", transition).component_id
        'sbox_0'
    """

    component_id: str
    transition: Transition

    def __post_init__(self) -> None:
        if not self.component_id:
            raise ValueError("trail step component_id must not be empty")


@dataclass(frozen=True, slots=True)
class Trail:
    """A checked sequence of component transitions.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import (Trail, TrailKind,
        ...     TrailStep, Transition, XorDifference)
        >>> transition = Transition(TrailKind.XOR_DIFFERENTIAL,
        ...     XorDifference(1, 1), XorDifference(1, 1), 1, 2)
        >>> trail = Trail(TrailKind.XOR_DIFFERENTIAL, XorDifference(1, 1),
        ...     XorDifference(1, 1), (TrailStep("sbox_0", transition),))
        >>> trail.total_weight
        1.0
    """

    kind: TrailKind
    input_pattern: BitPattern
    output_pattern: BitPattern
    steps: tuple[TrailStep, ...]

    def __post_init__(self) -> None:
        expected = XorDifference if self.kind is TrailKind.XOR_DIFFERENTIAL else XorMask
        if not isinstance(self.kind, TrailKind):
            raise TypeError("trail kind must be a TrailKind")
        if not isinstance(self.input_pattern, expected) or not isinstance(
            self.output_pattern, expected
        ):
            raise TypeError(f"{self.kind.value} trails require {expected.__name__} values")
        if any(step.transition.kind is not self.kind for step in self.steps):
            raise ValueError("every step must use the trail's propagation kind")

    @property
    def total_weight(self) -> float:
        """Return the sum of all component-transition weights."""
        return sum(step.transition.weight for step in self.steps)

    @property
    def semantics(self):
        """The representation-independent meaning propagated by this trail."""

        return self.kind.semantics

    def annotate(self, primitive, input_name: str = "plaintext"):
        """Attach this trail to ``primitive`` using the common graph annotation.

        The trail may contain only active components, so annotations are not
        required to cover the complete graph.
        """

        from claasp_next.annotations import AnnotationEntry, AnnotationRole, GraphAnnotation

        entries = [AnnotationEntry(input_name, AnnotationRole.INPUT, self.input_pattern)]
        entries.extend(
            AnnotationEntry(step.component_id, AnnotationRole.COMPONENT, step.transition)
            for step in self.steps
        )
        entries.append(AnnotationEntry("primitive_output", AnnotationRole.OUTPUT, self.output_pattern))
        return GraphAnnotation(primitive, self.semantics, entries)


@dataclass(frozen=True, slots=True)
class TrailSearchResult:
    """A trail together with its optimization claim and provenance.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import (Trail, TrailKind,
        ...     TrailSearchResult, XorDifference)
        >>> trail = Trail(TrailKind.XOR_DIFFERENTIAL, XorDifference(0, 1),
        ...     XorDifference(0, 1), ())
        >>> TrailSearchResult(trail, 0.0, "exhaustive").is_optimal
        True
    """

    trail: Trail
    lower_bound: float
    provenance: str

    @property
    def is_optimal(self) -> bool:
        """Return whether the trail meets the claimed lower bound."""
        return self.trail.total_weight == self.lower_bound


class SBoxTransitionSemantics:
    """Compute and independently check exact S-box DDT and LAT entries.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import SBoxTransitionSemantics
        >>> semantics = SBoxTransitionSemantics((0, 2, 3, 1))
        >>> transition = semantics.xor_differential(1, 2)
        >>> (transition.numerator, transition.denominator, semantics.check(transition))
        (4, 4, True)
    """

    def __init__(self, table: tuple[int, ...] | list[int]) -> None:
        self.table = tuple(table)
        size = len(self.table)
        if size < 2 or size & (size - 1):
            raise ValueError("S-box table size must be a power of two")
        self.width = size.bit_length() - 1
        if any(not isinstance(value, int) or not 0 <= value < size for value in self.table):
            raise ValueError("S-box values must fit the table width")

    def difference_distribution_table(self):
        """Return the complete exact integer DDT in quadratic time."""
        rows = []
        for alpha in range(len(self.table)):
            row = [0] * len(self.table)
            for value, output in enumerate(self.table):
                row[output ^ self.table[value ^ alpha]] += 1
            rows.append(tuple(row))
        return tuple(rows)

    def walsh_correlation_table(self):
        """Return full signed Walsh coefficients, not half-Walsh LAT counts."""
        size = len(self.table)
        rows = [[0] * size for _ in range(size)]
        for beta in range(size):
            values = [1 if (output & beta).bit_count() % 2 == 0 else -1 for output in self.table]
            stride = 1
            while stride < size:
                for start in range(0, size, 2 * stride):
                    for offset in range(stride):
                        left, right = values[start + offset], values[start + offset + stride]
                        values[start + offset], values[start + offset + stride] = left + right, left - right
                stride *= 2
            for alpha, coefficient in enumerate(values):
                rows[alpha][beta] = coefficient
        return tuple(tuple(row) for row in rows)

    def xor_differential(self, input_difference: int, output_difference: int) -> Transition:
        """Return the exact differential transition counted over all inputs."""

        self._validate_pattern(input_difference)
        self._validate_pattern(output_difference)
        count = sum(
            self.table[value] ^ self.table[value ^ input_difference] == output_difference
            for value in range(len(self.table))
        )
        return Transition(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(input_difference, self.width),
            XorDifference(output_difference, self.width),
            count,
            len(self.table),
        )

    def xor_linear(self, input_mask: int, output_mask: int) -> Transition:
        """Return the exact signed Walsh-correlation transition."""

        self._validate_pattern(input_mask)
        self._validate_pattern(output_mask)
        walsh = sum(
            1
            if ((value & input_mask).bit_count() + (self.table[value] & output_mask).bit_count())
            % 2
            == 0
            else -1
            for value in range(len(self.table))
        )
        return Transition(
            TrailKind.XOR_LINEAR,
            XorMask(input_mask, self.width),
            XorMask(output_mask, self.width),
            abs(walsh),
            len(self.table),
            -1 if walsh < 0 else 1,
        )

    def truncated_xor_differential(self, difference):
        """Join every compatible concrete derivative into undisturbed bits.

        This strongest bitwise abstraction is not a probability-bearing
        transition. Unknown output bits do not identify feasible joint values.
        """
        from .truncated import TruncatedBit, TruncatedXorDifference
        if not isinstance(difference, TruncatedXorDifference) or len(difference.bits) != self.width:
            raise ValueError("truncated difference must match the S-box width")
        outputs = set()
        for alpha in range(len(self.table)):
            if any(bit is not TruncatedBit.UNKNOWN and bit.encoded != ((alpha >> (self.width - 1 - position)) & 1)
                   for position, bit in enumerate(difference.bits)):
                continue
            outputs.update(self.table[x] ^ self.table[x ^ alpha] for x in range(len(self.table)))
        joined = []
        for position in range(self.width):
            values = {(output >> (self.width - 1 - position)) & 1 for output in outputs}
            joined.append(TruncatedBit.UNKNOWN if len(values) > 1 else
                          TruncatedBit.ONE if 1 in values else TruncatedBit.ZERO)
        return TruncatedXorDifference(tuple(joined))

    def check(self, transition: Transition) -> bool:
        """Recompute a transition without trusting a solver-provided weight."""

        if transition.kind is TrailKind.XOR_DIFFERENTIAL:
            expected = self.xor_differential(
                transition.input_pattern.value, transition.output_pattern.value
            )
        else:
            expected = self.xor_linear(
                transition.input_pattern.value, transition.output_pattern.value
            )
        return transition == expected

    def _validate_pattern(self, value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < len(self.table):
            raise ValueError(f"pattern must be an integer in range({len(self.table)})")


class ModularAddTransitionSemantics:
    """Exact XOR-differential semantics for two-input modular addition.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import ModularAddTransitionSemantics
        >>> semantics = ModularAddTransitionSemantics(2)
        >>> transition = semantics.xor_differential(0, 0, 0)
        >>> (transition.weight, semantics.check(transition), len(semantics.possible_transitions(0, 0)))
        (-0.0, True, 1)
    """

    def __init__(self, width: int) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise ValueError("modular-add width must be a positive integer")
        self.width = width
        self.mask = (1 << width) - 1

    def xor_differential(
        self, left_difference: int, right_difference: int, output_difference: int
    ) -> Transition:
        """Count a transition using a four-state paired-carry automaton."""

        for value in (left_difference, right_difference, output_difference):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= self.mask:
                raise ValueError(f"differences must be integers in range({self.mask + 1})")
        carries = {(0, 0): 1}
        for bit in range(self.width):
            next_carries = defaultdict(int)
            expected = (output_difference >> bit) & 1
            left_delta = (left_difference >> bit) & 1
            right_delta = (right_difference >> bit) & 1
            for (carry, paired_carry), count in carries.items():
                for left in (0, 1):
                    for right in (0, 1):
                        total = left + right + carry
                        paired_total = (
                            (left ^ left_delta) + (right ^ right_delta) + paired_carry
                        )
                        if ((total ^ paired_total) & 1) == expected:
                            next_carries[(total >> 1, paired_total >> 1)] += count
            carries = next_carries
        return Transition(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference((left_difference << self.width) | right_difference, 2 * self.width),
            XorDifference(output_difference, self.width),
            sum(carries.values()),
            1 << (2 * self.width),
        )

    def possible_transitions(
        self, left_difference: int, right_difference: int
    ) -> tuple[Transition, ...]:
        """Enumerate possible outputs, highest probability first."""

        for value in (left_difference, right_difference):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= self.mask:
                raise ValueError(f"differences must be integers in range({self.mask + 1})")
        states = {(0, 0, 0): 1}
        for bit in range(self.width):
            next_states = defaultdict(int)
            left_delta = (left_difference >> bit) & 1
            right_delta = (right_difference >> bit) & 1
            for (carry, paired_carry, output), count in states.items():
                for left in (0, 1):
                    for right in (0, 1):
                        total = left + right + carry
                        paired_total = (
                            (left ^ left_delta) + (right ^ right_delta) + paired_carry
                        )
                        difference = (total ^ paired_total) & 1
                        next_states[(
                            total >> 1,
                            paired_total >> 1,
                            output | (difference << bit),
                        )] += count
            states = next_states
        counts = defaultdict(int)
        for (_, _, output), count in states.items():
            counts[output] += count
        return tuple(
            sorted(
                (
                    Transition(
                        TrailKind.XOR_DIFFERENTIAL,
                        XorDifference(
                            (left_difference << self.width) | right_difference,
                            2 * self.width,
                        ),
                        XorDifference(output, self.width),
                        count,
                        1 << (2 * self.width),
                    )
                    for output, count in counts.items()
                ),
                key=lambda transition: (-transition.numerator, transition.output_pattern.value),
            )
        )

    def check(self, transition: Transition) -> bool:
        """Recompute a modular-add transition independently."""

        left = transition.input_pattern.value >> self.width
        right = transition.input_pattern.value & self.mask
        return transition == self.xor_differential(
            left, right, transition.output_pattern.value
        )


class ModularAddLinearSemantics:
    """Exact Walsh correlations for masks of two-input modular addition.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import ModularAddLinearSemantics
        >>> semantics = ModularAddLinearSemantics(2)
        >>> transition = semantics.xor_linear(0, 0, 0)
        >>> (transition.weight, semantics.check(transition))
        (-0.0, True)
    """

    def __init__(self, width: int) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise ValueError("modular-add width must be a positive integer")
        self.width = width
        self.mask = (1 << width) - 1

    def xor_linear(self, left_mask: int, right_mask: int, output_mask: int) -> Transition:
        """Compute an exact correlation with a two-state carry automaton."""

        for value in (left_mask, right_mask, output_mask):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= self.mask:
                raise ValueError(f"masks must be integers in range({self.mask + 1})")
        carries = {0: 1}
        for bit in range(self.width):
            next_carries = defaultdict(int)
            for carry, walsh in carries.items():
                for left in (0, 1):
                    for right in (0, 1):
                        total = left + right + carry
                        parity = (
                            (((left_mask >> bit) & 1) & left)
                            ^ (((right_mask >> bit) & 1) & right)
                            ^ (((output_mask >> bit) & 1) & (total & 1))
                        )
                        next_carries[total >> 1] += -walsh if parity else walsh
            carries = {carry: value for carry, value in next_carries.items() if value}
        walsh = sum(carries.values())
        return Transition(
            TrailKind.XOR_LINEAR,
            XorMask((left_mask << self.width) | right_mask, 2 * self.width),
            XorMask(output_mask, self.width),
            abs(walsh),
            1 << (2 * self.width),
            -1 if walsh < 0 else 1,
        )

    def check(self, transition: Transition) -> bool:
        """Recompute a modular-add linear transition independently."""

        left = transition.input_pattern.value >> self.width
        right = transition.input_pattern.value & self.mask
        return transition == self.xor_linear(left, right, transition.output_pattern.value)
