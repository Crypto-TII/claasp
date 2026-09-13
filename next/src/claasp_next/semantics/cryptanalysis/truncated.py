"""Backend-neutral deterministic truncated XOR-difference semantics."""

from dataclasses import dataclass
from enum import Enum

from claasp_next.components import Rotate
from claasp_next.graph import Cipher


class TruncatedBit(str, Enum):
    """A bit difference known as zero, known as one, or undetermined."""

    ZERO = "0"
    ONE = "1"
    UNKNOWN = "?"

    @property
    def encoded(self) -> int:
        """Return the conventional CP value 0, 1, or 2 for unknown."""

        return 2 if self is TruncatedBit.UNKNOWN else int(self.value)


class WordwiseDifferenceKind(int, Enum):
    """Legacy word-activity meanings, separated from their CP encoding."""

    ZERO = 0
    KNOWN = 1
    NONZERO = 2
    UNKNOWN = 3


@dataclass(frozen=True, slots=True)
class WordwiseXorDifference:
    """A zero, known, nonzero, or unrestricted XOR difference over one word."""

    width: int
    kind: WordwiseDifferenceKind
    value: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.width, int) or isinstance(self.width, bool) or self.width <= 0:
            raise ValueError("wordwise difference width must be positive")
        if not isinstance(self.kind, WordwiseDifferenceKind):
            raise TypeError("kind must be a WordwiseDifferenceKind")
        if self.kind is WordwiseDifferenceKind.ZERO:
            if self.value not in (None, 0):
                raise ValueError("zero wordwise differences cannot carry a nonzero value")
            object.__setattr__(self, "value", 0)
        elif self.kind is WordwiseDifferenceKind.KNOWN:
            if not isinstance(self.value, int) or isinstance(self.value, bool):
                raise TypeError("known wordwise differences require an integer value")
            if not 0 < self.value < (1 << self.width):
                raise ValueError("known wordwise difference must be nonzero and fit its width")
        elif self.value is not None:
            raise ValueError("abstract wordwise differences cannot carry a concrete value")

    @classmethod
    def known(cls, width: int, value: int) -> "WordwiseXorDifference":
        return cls(width, WordwiseDifferenceKind.KNOWN, value)

    def xor(self, other: "WordwiseXorDifference") -> "WordwiseXorDifference":
        """Return the strongest sound wordwise result of XOR."""

        if not isinstance(other, WordwiseXorDifference) or self.width != other.width:
            raise ValueError("wordwise XOR operands must have the same width")
        if self.kind is WordwiseDifferenceKind.ZERO:
            return other
        if other.kind is WordwiseDifferenceKind.ZERO:
            return self
        if self.kind is other.kind is WordwiseDifferenceKind.KNOWN:
            value = self.value ^ other.value
            return type(self)(self.width, WordwiseDifferenceKind.ZERO) if value == 0 else type(self).known(self.width, value)
        return type(self)(self.width, WordwiseDifferenceKind.UNKNOWN)

    def through_bijection(self) -> "WordwiseXorDifference":
        """Propagate activity through a bijection without claiming a value."""

        if self.kind is WordwiseDifferenceKind.ZERO:
            return self
        if self.kind in (WordwiseDifferenceKind.KNOWN, WordwiseDifferenceKind.NONZERO):
            return type(self)(self.width, WordwiseDifferenceKind.NONZERO)
        return self


@dataclass(frozen=True, slots=True)
class TruncatedXorDifference:
    """An MSB-first deterministic truncated XOR difference."""

    bits: tuple[TruncatedBit, ...]

    def __post_init__(self) -> None:
        if not self.bits or any(not isinstance(bit, TruncatedBit) for bit in self.bits):
            raise ValueError("a truncated difference requires TruncatedBit values")

    @classmethod
    def parse(cls, pattern: str) -> "TruncatedXorDifference":
        """Parse a user-facing string such as ``'001?10'``."""

        if not isinstance(pattern, str) or not pattern:
            raise ValueError("truncated pattern must be a non-empty string")
        try:
            return cls(tuple(TruncatedBit(bit) for bit in pattern))
        except ValueError as error:
            raise ValueError("truncated patterns may contain only '0', '1', and '?'") from error

    def __str__(self) -> str:
        return "".join(bit.value for bit in self.bits)

    def rotate_left(self, amount: int) -> "TruncatedXorDifference":
        amount %= len(self.bits)
        return type(self)(self.bits[amount:] + self.bits[:amount])

    def rotate_right(self, amount: int) -> "TruncatedXorDifference":
        return self.rotate_left(-amount)

    def xor(self, other: "TruncatedXorDifference") -> "TruncatedXorDifference":
        if len(self.bits) != len(other.bits):
            raise ValueError("truncated XOR operands must have equal width")
        output = []
        for left, right in zip(self.bits, other.bits):
            if TruncatedBit.UNKNOWN in (left, right):
                output.append(TruncatedBit.UNKNOWN)
            else:
                output.append(TruncatedBit.ONE if left is not right else TruncatedBit.ZERO)
        return type(self)(tuple(output))


@dataclass(frozen=True, slots=True)
class ProbabilisticTruncatedModularAddTransition:
    """One probability-bearing partial propagation through modular addition.

    ``costs`` use the legacy CLAASP fixed-point scale: 100 units represent a
    probability weight of one bit.
    """

    left: TruncatedXorDifference
    right: TruncatedXorDifference
    output: TruncatedXorDifference
    carry_difference: TruncatedXorDifference
    costs: tuple[int, ...]

    def __post_init__(self) -> None:
        width = len(self.left.bits)
        if any(len(pattern.bits) != width for pattern in (
            self.right, self.output, self.carry_difference,
        )) or len(self.costs) != width:
            raise ValueError("probabilistic truncated transition values must have equal widths")
        if any(cost not in {0, 4, 9, 19, 41, 100} for cost in self.costs):
            raise ValueError("invalid probabilistic truncated fixed-point cost")

    @property
    def scaled_weight(self) -> int:
        """Return the integral legacy fixed-point probability cost."""

        return sum(self.costs)

    @property
    def weight(self) -> float:
        """Return the probability weight in bits."""

        return self.scaled_weight / 100


@dataclass(frozen=True, slots=True)
class ProbabilisticTruncatedTrail:
    """A composed partial-difference trail with probability-bearing steps."""

    input_pattern: TruncatedXorDifference
    output_pattern: TruncatedXorDifference
    transitions: tuple[ProbabilisticTruncatedModularAddTransition, ...]

    @property
    def scaled_weight(self) -> int:
        return sum(transition.scaled_weight for transition in self.transitions)

    @property
    def weight(self) -> float:
        return self.scaled_weight / 100


def check_probabilistic_truncated_modular_add(
    transition: ProbabilisticTruncatedModularAddTransition,
) -> bool:
    """Check the legacy counter-based relation independently of MiniZinc."""

    if not isinstance(transition, ProbabilisticTruncatedModularAddTransition):
        raise TypeError("transition must be a ProbabilisticTruncatedModularAddTransition")
    a = tuple(bit.encoded for bit in transition.left.bits)
    b = tuple(bit.encoded for bit in transition.right.bits)
    c = tuple(bit.encoded for bit in transition.output.bits)
    carry = tuple(bit.encoded for bit in transition.carry_difference.bits)
    costs = transition.costs
    width = len(a)
    if carry[-1] != 0 or costs[-1] != 0:
        return False
    for index in range(width):
        expected = 2 if 2 in (a[index], b[index], carry[index]) else (
            a[index] + b[index] + carry[index]
        ) % 2
        if c[index] != expected:
            return False
    run_length = [0] * width
    for index in range(width - 2, -1, -1):
        if a[index + 1] + b[index + 1] == 0 and carry[index + 1] == 2:
            run_length[index] = run_length[index + 1] + 1
    discounted = {1: 41, 2: 19, 3: 9, 4: 4}
    for index in range(width - 1):
        if (a[index + 1], b[index + 1], c[index + 1]) == (0, 0, 0):
            allowed = {(0, 0)}
        elif (a[index + 1], b[index + 1], c[index + 1]) == (1, 1, 1):
            allowed = {(1, 0)}
        else:
            allowed = {(2, 0)}
            if run_length[index] == 0:
                allowed.update(((0, 100), (1, 100)))
            else:
                allowed.add((0, discounted.get(run_length[index], 0)))
        if (carry[index], costs[index]) not in allowed:
            return False
    return True


def truncated_modular_add(
    left: TruncatedXorDifference, right: TruncatedXorDifference
) -> TruncatedXorDifference:
    """Soundly propagate patterns through addition using paired carries."""

    if len(left.bits) != len(right.bits):
        raise ValueError("modular-add operands must have equal width")
    carries = {(0, 0)}
    lsb_output = []
    for left_bit, right_bit in zip(reversed(left.bits), reversed(right.bits)):
        outputs = set()
        next_carries = set()
        left_deltas = (0, 1) if left_bit is TruncatedBit.UNKNOWN else (int(left_bit.value),)
        right_deltas = (0, 1) if right_bit is TruncatedBit.UNKNOWN else (int(right_bit.value),)
        for carry, paired_carry in carries:
            for left_delta in left_deltas:
                for right_delta in right_deltas:
                    for left_value in (0, 1):
                        for right_value in (0, 1):
                            total = left_value + right_value + carry
                            paired = (left_value ^ left_delta) + (right_value ^ right_delta) + paired_carry
                            outputs.add((total ^ paired) & 1)
                            next_carries.add((total >> 1, paired >> 1))
        lsb_output.append(
            TruncatedBit.UNKNOWN if len(outputs) != 1
            else TruncatedBit.ONE if 1 in outputs else TruncatedBit.ZERO
        )
        carries = next_carries
    return TruncatedXorDifference(tuple(reversed(lsb_output)))


def propagate_two_word_speck_round(
    cipher: Cipher, difference: TruncatedXorDifference
) -> TruncatedXorDifference:
    """Propagate a zero-key-difference pattern through Speck's first round."""

    plaintext = cipher.inputs.get("plaintext")
    if cipher.family_name != "speck" or plaintext is None:
        raise ValueError("cipher must be Speck")
    width = plaintext.value_type.domain.width
    if len(difference.bits) != 2 * width:
        raise ValueError("difference width must match the Speck block")
    alpha = _rotation(cipher, "round_0_rotate_right").amount
    beta = _rotation(cipher, "round_0_rotate_left").amount
    left = TruncatedXorDifference(difference.bits[:width])
    right = TruncatedXorDifference(difference.bits[width:])
    new_left = truncated_modular_add(left.rotate_right(alpha), right)
    new_right = right.rotate_left(beta).xor(new_left)
    return TruncatedXorDifference(new_left.bits + new_right.bits)


def _rotation(cipher: Cipher, component_id: str) -> Rotate:
    component = next((item for item in cipher.components if item.component_id == component_id), None)
    if not isinstance(component, Rotate):
        raise ValueError(f"cipher is missing rotation {component_id!r}")
    return component
