"""Dependency-free continuous-correlation heuristics for ARX operations."""

from dataclasses import dataclass
from math import log2


@dataclass(frozen=True, slots=True)
class ContinuousHeuristicResult:
    """A numerical candidate that deliberately carries no proof status."""

    values: tuple[float, ...]
    tolerance: float
    provenance: str
    precision: str = "binary64"
    claim_kind: str = "heuristic"

    def __post_init__(self) -> None:
        if not self.values or any(not -1.0 <= value <= 1.0 for value in self.values):
            raise ValueError("continuous correlations must be nonempty and lie in [-1, 1]")
        if self.tolerance <= 0:
            raise ValueError("tolerance must be positive")
        if self.claim_kind != "heuristic":
            raise ValueError("continuous results cannot claim exact proof status")

    def selected_correlation(self, mask: tuple[int, ...]) -> float:
        """Multiply absolute correlations selected by a Boolean mask."""

        if len(mask) != len(self.values) or any(bit not in (0, 1) for bit in mask):
            raise ValueError("mask must be Boolean and match the result width")
        correlation = 1.0
        for bit, value in zip(mask, self.values):
            if bit:
                correlation *= abs(value)
        return correlation

    def selected_weight(self, mask: tuple[int, ...]) -> float:
        """Return ``-log2`` of a selected nonzero heuristic correlation."""

        correlation = self.selected_correlation(mask)
        return float("inf") if correlation == 0 else -log2(correlation)


def continuous_xor(left: tuple[float, ...], right: tuple[float, ...]) -> tuple[float, ...]:
    """Apply equation 5 of the preserved continuous ARX model bitwise."""

    _equal_vectors(left, right)
    return tuple(-a * b for a, b in zip(left, right))


def continuous_modular_add(left: tuple[float, ...], right: tuple[float, ...]) -> tuple[float, ...]:
    """Apply the continuous majority/carry approximation to modular addition."""

    _equal_vectors(left, right)
    carry = -1.0
    reversed_output = []
    for a, b in zip(reversed(left), reversed(right)):
        reversed_output.append(a * b * carry)
        carry = 0.25 * (a + b + carry + a * b * carry)
    return tuple(reversed(reversed_output))


def continuous_rotate_left(values: tuple[float, ...], amount: int) -> tuple[float, ...]:
    """Rotate a big-endian correlation vector left."""

    amount = _rotation(values, amount)
    return values[amount:] + values[:amount]


def continuous_rotate_right(values: tuple[float, ...], amount: int) -> tuple[float, ...]:
    """Rotate a big-endian correlation vector right."""

    amount = _rotation(values, amount)
    return values[-amount:] + values[:-amount] if amount else values


def continuous_speck32(
    left: tuple[float, ...], right: tuple[float, ...], *, rounds: int
) -> ContinuousHeuristicResult:
    """Propagate the legacy continuous model through reduced Speck32/64.

    Key and round-counter differences are fixed to zero (correlation ``-1``),
    matching the result-bearing legacy fixtures.
    """

    _equal_vectors(left, right)
    if len(left) != 16:
        raise ValueError("Speck32 continuous propagation requires 16-bit words")
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 22:
        raise ValueError("rounds must be between 1 and 22")
    zero_difference = (-1.0,) * 16
    for _ in range(rounds):
        left = continuous_modular_add(continuous_rotate_right(left, 7), right)
        left = continuous_xor(left, zero_difference)
        right = continuous_xor(continuous_rotate_left(right, 2), left)
    return ContinuousHeuristicResult(
        left + right, 1e-4,
        "legacy CLAASP continuous Speck model; BGGMP2023 equations 3--5",
    )


def _equal_vectors(left: tuple[float, ...], right: tuple[float, ...]) -> None:
    if not left or len(left) != len(right):
        raise ValueError("continuous operands must be nonempty and have equal width")
    if any(not -1.0 <= value <= 1.0 for value in left + right):
        raise ValueError("continuous correlations must lie in [-1, 1]")


def _rotation(values: tuple[float, ...], amount: int) -> int:
    if not values:
        raise ValueError("cannot rotate an empty vector")
    if not isinstance(amount, int) or isinstance(amount, bool):
        raise TypeError("rotation amount must be an integer")
    return amount % len(values)
