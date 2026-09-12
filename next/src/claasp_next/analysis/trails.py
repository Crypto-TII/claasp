"""Backend-independent differential and linear trail semantics."""

from dataclasses import dataclass
from enum import Enum
from math import inf, log2


class TrailKind(str, Enum):
    """The propagation semantics represented by a trail."""

    XOR_DIFFERENTIAL = "xor_differential"
    XOR_LINEAR = "xor_linear"


@dataclass(frozen=True, slots=True)
class BitPattern:
    """A fixed-width difference or mask represented as an integer."""

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
    """An XOR difference at a typed graph boundary."""


@dataclass(frozen=True, slots=True)
class XorMask(BitPattern):
    """An XOR linear mask at a typed graph boundary."""


@dataclass(frozen=True, slots=True)
class Transition:
    """One exact component transition and its probability/correlation weight."""

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
        return self.numerator != 0

    @property
    def weight(self) -> float:
        """Return ``-log2(probability)`` or ``-log2(abs(correlation))``."""

        return inf if not self.numerator else -log2(self.numerator / self.denominator)


@dataclass(frozen=True, slots=True)
class TrailStep:
    """A named component transition in a trail."""

    component_id: str
    transition: Transition

    def __post_init__(self) -> None:
        if not self.component_id:
            raise ValueError("trail step component_id must not be empty")


@dataclass(frozen=True, slots=True)
class Trail:
    """A checked sequence of component transitions."""

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
        return sum(step.transition.weight for step in self.steps)


@dataclass(frozen=True, slots=True)
class TrailSearchResult:
    """A trail together with its optimization claim and provenance."""

    trail: Trail
    lower_bound: float
    provenance: str

    @property
    def is_optimal(self) -> bool:
        return self.trail.total_weight == self.lower_bound


class SBoxTransitionSemantics:
    """Compute and independently check exact S-box DDT and LAT entries."""

    def __init__(self, table: tuple[int, ...] | list[int]) -> None:
        self.table = tuple(table)
        size = len(self.table)
        if size < 2 or size & (size - 1):
            raise ValueError("S-box table size must be a power of two")
        self.width = size.bit_length() - 1
        if any(not isinstance(value, int) or not 0 <= value < size for value in self.table):
            raise ValueError("S-box values must fit the table width")

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
