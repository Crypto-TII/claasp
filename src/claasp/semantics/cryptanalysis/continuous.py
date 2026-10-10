"""Dependency-free continuous-correlation heuristics for ARX operations."""

from dataclasses import dataclass
from math import log2


@dataclass(frozen=True, slots=True)
class ContinuousHeuristicResult:
    """A numerical candidate that deliberately carries no proof status.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis import ContinuousHeuristicResult
        >>> result = ContinuousHeuristicResult((0.5, -0.25), 1e-4, "fixed model")
        >>> (result.selected_correlation((1, 1)), result.selected_weight((1, 0)))
        (0.125, 1.0)
    """

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
    """Apply equation 5 of the preserved continuous ARX model bitwise.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis import continuous_xor
        >>> continuous_xor((-1.0, 0.5), (1.0, -0.5))
        (1.0, 0.25)
    """

    _equal_vectors(left, right)
    return tuple(-a * b for a, b in zip(left, right))


def continuous_and(left: tuple[float, ...], right: tuple[float, ...]) -> tuple[float, ...]:
    """Apply the MUR2020 continuous extension of Boolean AND.

    EXAMPLES::

        >>> continuous_and((-1.0,), (1.0,))
        (-1.0,)
    """

    _equal_vectors(left, right)
    return tuple((a * b + a + b - 1.0) / 2.0 for a, b in zip(left, right))


def continuous_or(left: tuple[float, ...], right: tuple[float, ...]) -> tuple[float, ...]:
    """Apply the MUR2020 continuous extension of Boolean OR.

    EXAMPLES::

        >>> continuous_or((-1.0,), (1.0,))
        (1.0,)
    """

    _equal_vectors(left, right)
    return tuple((-a * b + a + b + 1.0) / 2.0 for a, b in zip(left, right))


def continuous_not(values: tuple[float, ...]) -> tuple[float, ...]:
    """Apply the continuous extension of Boolean complement.

    EXAMPLES::

        >>> continuous_not((-1.0, 1.0))
        (1.0, -1.0)
    """

    _vector(values)
    return tuple(-value for value in values)


def continuous_modular_add(left: tuple[float, ...], right: tuple[float, ...]) -> tuple[float, ...]:
    """Apply the continuous majority/carry approximation to modular addition.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis import continuous_modular_add
        >>> continuous_modular_add((-1.0, -1.0), (-1.0, -1.0))
        (-1.0, -1.0)
    """

    _equal_vectors(left, right)
    carry = -1.0
    reversed_output = []
    for a, b in zip(reversed(left), reversed(right)):
        reversed_output.append(a * b * carry)
        carry = 0.25 * (a + b + carry + a * b * carry)
    return tuple(reversed(reversed_output))


def continuous_rotate_left(values: tuple[float, ...], amount: int) -> tuple[float, ...]:
    """Rotate a big-endian correlation vector left.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis import continuous_rotate_left
        >>> continuous_rotate_left((1.0, 0.0, -1.0), 1)
        (0.0, -1.0, 1.0)
    """

    amount = _rotation(values, amount)
    return values[amount:] + values[:amount]


def continuous_rotate_right(values: tuple[float, ...], amount: int) -> tuple[float, ...]:
    """Rotate a big-endian correlation vector right.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis import continuous_rotate_right
        >>> continuous_rotate_right((1.0, 0.0, -1.0), 1)
        (-1.0, 1.0, 0.0)
    """

    amount = _rotation(values, amount)
    return values[-amount:] + values[:-amount] if amount else values


def continuous_shift_left(values: tuple[float, ...], amount: int) -> tuple[float, ...]:
    """Shift a big-endian vector left, filling with fixed-zero correlations.

    EXAMPLES::

        >>> continuous_shift_left((-1.0, 0.0, 1.0), 1)
        (0.0, 1.0, -1.0)
    """

    amount = _shift(values, amount)
    if amount >= len(values):
        return (-1.0,) * len(values)
    return values[amount:] + (-1.0,) * amount


def continuous_shift_right(values: tuple[float, ...], amount: int) -> tuple[float, ...]:
    """Shift a big-endian vector right, filling with fixed-zero correlations.

    EXAMPLES::

        >>> continuous_shift_right((-1.0, 0.0, 1.0), 1)
        (-1.0, -1.0, 0.0)
    """

    amount = _shift(values, amount)
    if amount >= len(values):
        return (-1.0,) * len(values)
    return (-1.0,) * amount + values[: len(values) - amount]


def continuous_variable_rotate(
    values: tuple[float, ...], amount_bits: tuple[float, ...], *, direction: str
) -> tuple[float, ...]:
    """Apply the legacy staged-multiplexer heuristic to a variable rotation.

    ``amount_bits`` are supplied most-significant bit first, like graph word
    encodings. At Boolean endpoints this is exactly the ordinary variable
    rotation; fractional selectors retain the legacy continuous gate model.

    EXAMPLES::

        >>> continuous_variable_rotate((1.0, -1.0, -1.0, -1.0), (-1.0, 1.0), direction="right")
        (-1.0, 1.0, -1.0, -1.0)
    """

    _vector(values)
    _vector(amount_bits)
    if direction not in {"left", "right"}:
        raise ValueError("rotation direction must be 'left' or 'right'")
    current = values
    operation = continuous_rotate_left if direction == "left" else continuous_rotate_right
    for stage, selector in enumerate(reversed(amount_bits)):
        current = _continuous_mux(operation(current, 1 << stage), current, selector)
    return current


def continuous_variable_shift(
    values: tuple[float, ...], amount_bits: tuple[float, ...], *, direction: str
) -> tuple[float, ...]:
    """Apply the legacy staged-multiplexer heuristic to a variable shift.

    EXAMPLES::

        >>> continuous_variable_shift((1.0, -1.0, -1.0, -1.0), (-1.0, 1.0), direction="right")
        (-1.0, 1.0, -1.0, -1.0)
    """

    _vector(values)
    _vector(amount_bits)
    if direction not in {"left", "right"}:
        raise ValueError("shift direction must be 'left' or 'right'")
    current = values
    operation = continuous_shift_left if direction == "left" else continuous_shift_right
    for stage, selector in enumerate(reversed(amount_bits)):
        current = _continuous_mux(operation(current, 1 << stage), current, selector)
    return current


def continuous_sbox(values: tuple[float, ...], table: tuple[int, ...]) -> tuple[float, ...]:
    """Evaluate the exact multilinear extension of a finite lookup table.

    This dependency-free form is equivalent to the legacy Sage/NumPy
    precomputation, but computes expectations directly and supports rectangular
    bit-vector S-boxes as well as square word/field S-boxes.

    EXAMPLES::

        >>> continuous_sbox((-1.0, 1.0), (3, 2, 1, 0))
        (1.0, -1.0)
    """

    _vector(values)
    if len(table) != 1 << len(values):
        raise ValueError("S-box table size must match the input correlation width")
    output_width = max(1, max(table).bit_length())
    if any(value < 0 or value >= 1 << output_width for value in table):
        raise ValueError("S-box table entries must be nonnegative and fit one width")
    output = []
    for output_shift in reversed(range(output_width)):
        expectation = 0.0
        for source, target in enumerate(table):
            probability = 1.0
            for index, correlation in enumerate(values):
                bit = (source >> (len(values) - 1 - index)) & 1
                probability *= (1.0 + correlation if bit else 1.0 - correlation) / 2.0
            expectation += probability * (1.0 if (target >> output_shift) & 1 else -1.0)
        output.append(expectation)
    return tuple(output)


def continuous_speck32(
    left: tuple[float, ...], right: tuple[float, ...], *, rounds: int
) -> ContinuousHeuristicResult:
    """Propagate the legacy continuous model through reduced Speck32/64.

    Key and round-counter differences are fixed to zero (correlation ``-1``),
    matching the result-bearing legacy fixtures.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis import continuous_speck32
        >>> result = continuous_speck32((-1.0,) * 16, (-1.0,) * 16, rounds=1)
        >>> (len(result.values), result.claim_kind)
        (32, 'heuristic')
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
        left + right,
        1e-4,
        "legacy CLAASP continuous Speck model; BGGMP2023 equations 3--5",
    )


def _equal_vectors(left: tuple[float, ...], right: tuple[float, ...]) -> None:
    if not left or len(left) != len(right):
        raise ValueError("continuous operands must be nonempty and have equal width")
    if any(not -1.0 <= value <= 1.0 for value in left + right):
        raise ValueError("continuous correlations must lie in [-1, 1]")


def _continuous_mux(
    selected: tuple[float, ...], unselected: tuple[float, ...], selector: float
) -> tuple[float, ...]:
    """Reproduce the legacy NAND-composed continuous two-input multiplexer."""

    _equal_vectors(selected, unselected)
    if not -1.0 <= selector <= 1.0:
        raise ValueError("continuous selector must lie in [-1, 1]")

    def and_bit(left, right):
        return (left * right + left + right - 1.0) / 2.0

    output = []
    for first, second in zip(selected, unselected):
        first_nand = -and_bit(first, selector)
        selector_nand = -and_bit(selector, selector)
        second_nand = -and_bit(selector_nand, second)
        output.append(-and_bit(first_nand, second_nand))
    return tuple(output)


def _vector(values: tuple[float, ...]) -> None:
    if not values:
        raise ValueError("continuous vectors must be nonempty")
    if any(not -1.0 <= value <= 1.0 for value in values):
        raise ValueError("continuous correlations must lie in [-1, 1]")


def _rotation(values: tuple[float, ...], amount: int) -> int:
    if not values:
        raise ValueError("cannot rotate an empty vector")
    if not isinstance(amount, int) or isinstance(amount, bool):
        raise TypeError("rotation amount must be an integer")
    return amount % len(values)


def _shift(values: tuple[float, ...], amount: int) -> int:
    _vector(values)
    if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
        raise ValueError("shift amount must be a nonnegative integer")
    return amount
