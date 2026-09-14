"""Representation-independent contracts for composed cryptanalytic attacks."""

from dataclasses import dataclass
from math import log2

from claasp_next.semantics.cryptanalysis.trails import Trail, TrailKind, XorDifference
from claasp_next.semantics.cryptanalysis.truncated import ProbabilisticTruncatedTrail


@dataclass(frozen=True, slots=True)
class BoomerangConnectivity:
    """One exact BCT entry for a bijective finite lookup table."""

    input_difference: XorDifference
    output_difference: XorDifference
    count: int

    def __post_init__(self) -> None:
        if self.input_difference.width != self.output_difference.width:
            raise ValueError("BCT differences must have equal widths")
        size = 1 << self.input_difference.width
        if not isinstance(self.count, int) or isinstance(self.count, bool) or not 0 <= self.count <= size:
            raise ValueError("BCT count must lie between zero and the table size")

    @property
    def is_possible(self) -> bool:
        return self.count > 0

    @property
    def weight(self) -> float:
        return float("inf") if not self.count else -log2(self.count / (1 << self.input_difference.width))


class SBoxBoomerangSemantics:
    """Exhaustive boomerang-connectivity semantics for a bijective S-box."""

    def __init__(self, table) -> None:
        self.table = tuple(table)
        size = len(self.table)
        if size < 2 or size & (size - 1) or sorted(self.table) != list(range(size)):
            raise ValueError("boomerang connectivity requires a bijective power-of-two table")
        self.width = size.bit_length() - 1
        inverse = [0] * size
        for source, target in enumerate(self.table):
            inverse[target] = source
        self.inverse = tuple(inverse)

    def connectivity(self, input_difference: int, output_difference: int) -> BoomerangConnectivity:
        """Return the exact BCT count by exhaustive evaluation."""

        size = len(self.table)
        if not 0 <= input_difference < size or not 0 <= output_difference < size:
            raise ValueError("BCT differences must fit the S-box width")
        count = sum(
            (self.inverse[self.table[source] ^ output_difference] ^
             self.inverse[self.table[source ^ input_difference] ^ output_difference]) == input_difference
            for source in range(size)
        )
        return BoomerangConnectivity(
            XorDifference(input_difference, self.width),
            XorDifference(output_difference, self.width), count,
        )


@dataclass(frozen=True, slots=True)
class BoomerangSwitchBoundary:
    """Four XOR differences related by one boomerang switch."""

    upper_input: XorDifference
    upper_output: XorDifference
    lower_input: XorDifference
    lower_output: XorDifference
    weight: float

    def __post_init__(self) -> None:
        values = (self.upper_input, self.upper_output, self.lower_input, self.lower_output)
        if len({value.width for value in values}) != 1:
            raise ValueError("boomerang switch differences must have one width")
        if self.weight < 0:
            raise ValueError("boomerang switch weight cannot be negative")


@dataclass(frozen=True, slots=True)
class BoomerangTrail:
    """Two differential trails joined by an explicit switch boundary."""

    upper: Trail
    switch: BoomerangSwitchBoundary
    lower: Trail

    def __post_init__(self) -> None:
        if self.upper.kind is not TrailKind.XOR_DIFFERENTIAL or self.lower.kind is not TrailKind.XOR_DIFFERENTIAL:
            raise TypeError("boomerang constituents must be XOR-differential trails")
        if self.upper.output_pattern != self.switch.upper_input:
            raise ValueError("upper trail does not meet the switch boundary")
        if self.lower.input_pattern != self.switch.lower_output:
            raise ValueError("lower trail does not leave the switch boundary")

    @property
    def total_weight(self) -> float:
        return self.upper.total_weight + self.switch.weight + self.lower.total_weight


@dataclass(frozen=True, slots=True)
class DifferentialLinearTrail:
    """Differential prefix, probabilistic connector, and linear suffix."""

    differential: Trail
    connector: ProbabilisticTruncatedTrail
    linear: Trail

    def __post_init__(self) -> None:
        if self.differential.kind is not TrailKind.XOR_DIFFERENTIAL:
            raise TypeError("prefix must be an XOR-differential trail")
        if self.linear.kind is not TrailKind.XOR_LINEAR:
            raise TypeError("suffix must be an XOR-linear trail")
        widths = (self.differential.output_pattern.width,
                  len(self.connector.input_pattern.bits), self.linear.input_pattern.width)
        if len(set(widths)) != 1:
            raise ValueError("differential-linear boundaries must have one width")

    @property
    def total_weight(self) -> float:
        """Return the legacy exact objective ``p + log2(2^(r+1)-1) + 2q``."""

        p, r, q = self.differential.total_weight, self.connector.weight, self.linear.total_weight
        middle = log2((2 ** (r + 1)) - 1)
        return p + middle + 2 * q
