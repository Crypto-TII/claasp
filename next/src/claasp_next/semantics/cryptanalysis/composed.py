"""Representation-independent contracts for composed cryptanalytic attacks."""

from dataclasses import dataclass
from math import log2

from claasp_next.semantics.cryptanalysis.trails import Trail, TrailKind, XorDifference
from claasp_next.semantics.cryptanalysis.truncated import ProbabilisticTruncatedTrail


@dataclass(frozen=True, slots=True)
class BoomerangConnectivity:
    """One exact BCT entry for a bijective finite lookup table.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import BoomerangConnectivity, XorDifference
        >>> entry = BoomerangConnectivity(XorDifference(1, 2), XorDifference(2, 2), 2)
        >>> (entry.is_possible, entry.weight)
        (True, 1.0)
    """

    input_difference: XorDifference
    output_difference: XorDifference
    count: int

    def __post_init__(self) -> None:
        if self.input_difference.width != self.output_difference.width:
            raise ValueError("BCT differences must have equal widths")
        size = 1 << self.input_difference.width
        if (
            not isinstance(self.count, int)
            or isinstance(self.count, bool)
            or not 0 <= self.count <= size
        ):
            raise ValueError("BCT count must lie between zero and the table size")

    @property
    def is_possible(self) -> bool:
        """Return whether at least one boomerang quartet exists."""
        return self.count > 0

    @property
    def weight(self) -> float:
        """Return the negative binary logarithm of the BCT probability."""
        return (
            float("inf")
            if not self.count
            else -log2(self.count / (1 << self.input_difference.width))
        )


class SBoxBoomerangSemantics:
    """Exhaustive boomerang-connectivity semantics for a bijective S-box.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import SBoxBoomerangSemantics
        >>> SBoxBoomerangSemantics((0, 2, 3, 1)).connectivity(1, 2).count
        4
    """

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
        """Return the exact BCT count by exhaustive evaluation.

        EXAMPLES::

            >>> from claasp_next.semantics.cryptanalysis import SBoxBoomerangSemantics
            >>> SBoxBoomerangSemantics((0, 1)).connectivity(1, 1).is_possible
            True
        """

        size = len(self.table)
        if not 0 <= input_difference < size or not 0 <= output_difference < size:
            raise ValueError("BCT differences must fit the S-box width")
        count = sum(
            (
                self.inverse[self.table[source] ^ output_difference]
                ^ self.inverse[self.table[source ^ input_difference] ^ output_difference]
            )
            == input_difference
            for source in range(size)
        )
        return BoomerangConnectivity(
            XorDifference(input_difference, self.width),
            XorDifference(output_difference, self.width),
            count,
        )


@dataclass(frozen=True, slots=True)
class ModularAddBoomerangConnectivity:
    """Exact quartet count for four differences around modular addition.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import (ModularAddBoomerangConnectivity,
        ...     XorDifference)
        >>> zero = XorDifference(0, 2)
        >>> entry = ModularAddBoomerangConnectivity(zero, zero, zero, zero, 16)
        >>> (entry.is_possible, entry.weight)
        (True, -0.0)
    """

    delta_left: XorDifference
    delta_right: XorDifference
    nabla_output: XorDifference
    nabla_right: XorDifference
    count: int

    def __post_init__(self) -> None:
        differences = (self.delta_left, self.delta_right, self.nabla_output, self.nabla_right)
        if len({item.width for item in differences}) != 1:
            raise ValueError("modular-add switch differences must have one width")
        maximum = 1 << (2 * self.delta_left.width)
        if (
            not isinstance(self.count, int)
            or isinstance(self.count, bool)
            or not 0 <= self.count <= maximum
        ):
            raise ValueError("quartet count is outside the modular-add input space")

    @property
    def is_possible(self) -> bool:
        """Return whether at least one modular-add quartet exists."""
        return self.count > 0

    @property
    def weight(self) -> float:
        """Return the exact negative-log quartet probability."""
        size = 1 << (2 * self.delta_left.width)
        return float("inf") if not self.count else -log2(self.count / size)


class ModularAddBoomerangSemantics:
    """Exact boomerang-switch oracle for small modular-add word sizes.

    The exhaustive implementation is deliberately limited to eight-bit words.
    It serves as an independent oracle for optimized bit-automaton lowerings.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import ModularAddBoomerangSemantics
        >>> ModularAddBoomerangSemantics(2).connectivity(0, 0, 0, 0).count
        16
    """

    def __init__(self, width: int) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or not 1 <= width <= 8:
            raise ValueError("the exhaustive modular-add oracle supports widths 1 through 8")
        self.width = width

    def connectivity(self, delta_left, delta_right, nabla_output, nabla_right):
        """Count quartets satisfying the modular-add switch equations.

        EXAMPLES::

            >>> from claasp_next.semantics.cryptanalysis import ModularAddBoomerangSemantics
            >>> ModularAddBoomerangSemantics(4).connectivity(1, 0, 1, 0).weight
            1.0
        """

        size, mask = 1 << self.width, (1 << self.width) - 1
        values = (delta_left, delta_right, nabla_output, nabla_right)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < size
            for value in values
        ):
            raise ValueError("switch differences must fit the word width")
        count = 0
        for left in range(size):
            for right in range(size):
                output = (left + right) & mask
                paired_output = ((left ^ delta_left) + (right ^ delta_right)) & mask
                lower_right = right ^ nabla_right
                lower_paired_right = (right ^ delta_right) ^ nabla_right
                lower_left = ((output ^ nabla_output) - lower_right) & mask
                lower_paired_left = ((paired_output ^ nabla_output) - lower_paired_right) & mask
                if lower_left ^ lower_paired_left == delta_left:
                    count += 1
        difference = lambda value: XorDifference(value, self.width)
        return ModularAddBoomerangConnectivity(
            difference(delta_left),
            difference(delta_right),
            difference(nabla_output),
            difference(nabla_right),
            count,
        )


class ModularAddBoomerangAutomaton:
    """Exact scalable modular-add switch using carry/borrow states.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import ModularAddBoomerangAutomaton
        >>> ModularAddBoomerangAutomaton(16).connectivity(1, 0, 1, 0).weight
        1.0
    """

    def __init__(self, width: int) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or not 1 <= width <= 64:
            raise ValueError("the modular-add switch automaton supports widths 1 through 64")
        self.width = width

    def connectivity(self, delta_left, delta_right, nabla_output, nabla_right):
        """Count quartets with a sixteen-state least-significant-bit automaton.

        EXAMPLES::

            >>> from claasp_next.semantics.cryptanalysis import ModularAddBoomerangAutomaton
            >>> ModularAddBoomerangAutomaton(3).connectivity(0, 0, 0, 0).count
            64
        """

        size = 1 << self.width
        values = (delta_left, delta_right, nabla_output, nabla_right)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < size
            for value in values
        ):
            raise ValueError("switch differences must fit the word width")
        states = {(0, 0, 0, 0): 1}
        for bit in range(self.width):
            da = (delta_left >> bit) & 1
            dr = (delta_right >> bit) & 1
            no = (nabla_output >> bit) & 1
            nr = (nabla_right >> bit) & 1
            following = {}
            for (carry, paired_carry, borrow, paired_borrow), paths in states.items():
                for left_bit in (0, 1):
                    for right_bit in (0, 1):
                        top = left_bit + right_bit + carry
                        paired_top = (left_bit ^ da) + (right_bit ^ dr) + paired_carry
                        lower_total = ((top & 1) ^ no) - (right_bit ^ nr) - borrow
                        paired_lower_total = (
                            ((paired_top & 1) ^ no) - ((right_bit ^ dr) ^ nr) - paired_borrow
                        )
                        if ((lower_total & 1) ^ (paired_lower_total & 1)) != da:
                            continue
                        state = (
                            top >> 1,
                            paired_top >> 1,
                            int(lower_total < 0),
                            int(paired_lower_total < 0),
                        )
                        following[state] = following.get(state, 0) + paths
            states = following
        count = sum(states.values())
        difference = lambda value: XorDifference(value, self.width)
        return ModularAddBoomerangConnectivity(
            difference(delta_left),
            difference(delta_right),
            difference(nabla_output),
            difference(nabla_right),
            count,
        )


@dataclass(frozen=True, slots=True)
class BoomerangSwitchBoundary:
    """Four XOR differences related by one boomerang switch.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import BoomerangSwitchBoundary, XorDifference
        >>> values = tuple(XorDifference(value, 2) for value in range(4))
        >>> BoomerangSwitchBoundary(*values, 1.5).weight
        1.5
    """

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
    """Two differential trails joined by an explicit switch boundary.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import *
        >>> upper = Trail(TrailKind.XOR_DIFFERENTIAL, XorDifference(1, 2), XorDifference(2, 2), ())
        >>> lower = Trail(TrailKind.XOR_DIFFERENTIAL, XorDifference(3, 2), XorDifference(0, 2), ())
        >>> switch = BoomerangSwitchBoundary(XorDifference(2, 2), XorDifference(1, 2),
        ...     XorDifference(0, 2), XorDifference(3, 2), 1.5)
        >>> BoomerangTrail(upper, switch, lower).total_weight
        1.5
    """

    upper: Trail
    switch: BoomerangSwitchBoundary
    lower: Trail

    def __post_init__(self) -> None:
        if (
            self.upper.kind is not TrailKind.XOR_DIFFERENTIAL
            or self.lower.kind is not TrailKind.XOR_DIFFERENTIAL
        ):
            raise TypeError("boomerang constituents must be XOR-differential trails")
        if self.upper.output_pattern != self.switch.upper_input:
            raise ValueError("upper trail does not meet the switch boundary")
        if self.lower.input_pattern != self.switch.lower_output:
            raise ValueError("lower trail does not leave the switch boundary")

    @property
    def total_weight(self) -> float:
        """Return the combined upper, switch, and lower weight."""
        return self.upper.total_weight + self.switch.weight + self.lower.total_weight


@dataclass(frozen=True, slots=True)
class DifferentialLinearTrail:
    """Differential prefix, probabilistic connector, and linear suffix.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import *
        >>> differential = Trail(TrailKind.XOR_DIFFERENTIAL, XorDifference(1, 2), XorDifference(2, 2), ())
        >>> linear = Trail(TrailKind.XOR_LINEAR, XorMask(1, 2), XorMask(2, 2), ())
        >>> connector = ProbabilisticTruncatedTrail(
        ...     TruncatedXorDifference.parse("00"), TruncatedXorDifference.parse("??"), ())
        >>> DifferentialLinearTrail(differential, connector, linear).total_weight
        0.0
    """

    differential: Trail
    connector: ProbabilisticTruncatedTrail
    linear: Trail

    def __post_init__(self) -> None:
        if self.differential.kind is not TrailKind.XOR_DIFFERENTIAL:
            raise TypeError("prefix must be an XOR-differential trail")
        if self.linear.kind is not TrailKind.XOR_LINEAR:
            raise TypeError("suffix must be an XOR-linear trail")
        widths = (
            self.differential.output_pattern.width,
            len(self.connector.input_pattern.bits),
            self.linear.input_pattern.width,
        )
        if len(set(widths)) != 1:
            raise ValueError("differential-linear boundaries must have one width")

    @property
    def total_weight(self) -> float:
        """Return the legacy exact objective ``p + log2(2^(r+1)-1) + 2q``."""

        p, r, q = self.differential.total_weight, self.connector.weight, self.linear.total_weight
        middle = log2((2 ** (r + 1)) - 1)
        return p + middle + 2 * q
