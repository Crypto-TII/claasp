"""Deterministic truncated XOR-difference semantics."""

from dataclasses import dataclass
from enum import Enum

from claasp_next.components import Rotate
from claasp_next.core import Cipher


class TruncatedBit(str, Enum):
    """A bit difference known as zero, known as one, or undetermined."""

    ZERO = "0"
    ONE = "1"
    UNKNOWN = "?"


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


def truncated_modular_add(
    left: TruncatedXorDifference, right: TruncatedXorDifference
) -> TruncatedXorDifference:
    """Soundly propagate two truncated differences through modular addition.

    A paired-carry reachability automaton explores all concrete difference and
    value bits represented by the input patterns. An output bit is retained
    only when every reachable transition agrees on it.
    """

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
                            paired = (
                                (left_value ^ left_delta)
                                + (right_value ^ right_delta)
                                + paired_carry
                            )
                            outputs.add((total ^ paired) & 1)
                            next_carries.add((total >> 1, paired >> 1))
        lsb_output.append(
            TruncatedBit.UNKNOWN
            if len(outputs) != 1
            else TruncatedBit.ONE
            if 1 in outputs
            else TruncatedBit.ZERO
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
