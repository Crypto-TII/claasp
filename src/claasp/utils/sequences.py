"""Sage-independent rotation and shifting of homogeneous sequences."""

from collections.abc import Sequence
from typing import TypeVar, overload

T = TypeVar("T")


def _validate(sequence: Sequence[T], amount: int) -> None:
    if not isinstance(sequence, (list, tuple)):
        raise TypeError("sequence must be a list or tuple")
    if not isinstance(amount, int) or isinstance(amount, bool):
        raise TypeError("amount must be an integer")
    if amount < 0:
        raise ValueError("amount must be non-negative")


@overload
def rotate_right(sequence: list[T], amount: int) -> list[T]: ...


@overload
def rotate_right(sequence: tuple[T, ...], amount: int) -> tuple[T, ...]: ...


def rotate_right(sequence: list[T] | tuple[T, ...], amount: int) -> list[T] | tuple[T, ...]:
    """Return a right-rotated sequence of the same concrete type.

    EXAMPLES::

        >>> from claasp.utils import rotate_sequence_right
        >>> rotate_sequence_right([1, 2, 3, 4, 5], 2)
        [4, 5, 1, 2, 3]
    """

    _validate(sequence, amount)
    if not sequence:
        return sequence
    amount %= len(sequence)
    if amount == 0:
        return sequence[:]
    if isinstance(sequence, list):
        return sequence[-amount:] + sequence[:-amount]
    return sequence[-amount:] + sequence[:-amount]


@overload
def rotate_left(sequence: list[T], amount: int) -> list[T]: ...


@overload
def rotate_left(sequence: tuple[T, ...], amount: int) -> tuple[T, ...]: ...


def rotate_left(sequence: list[T] | tuple[T, ...], amount: int) -> list[T] | tuple[T, ...]:
    """Return a left-rotated sequence of the same concrete type.

    EXAMPLES::

        >>> rotate_left((1, 2, 3), 1)
        (2, 3, 1)
    """

    _validate(sequence, amount)
    if not sequence:
        return sequence
    return rotate_right(sequence, (-amount) % len(sequence))


@overload
def shift_right(sequence: list[T], amount: int, *, fill: T | int = 0) -> list[T | int]: ...


@overload
def shift_right(
    sequence: tuple[T, ...], amount: int, *, fill: T | int = 0
) -> tuple[T | int, ...]: ...


def shift_right(
    sequence: list[T] | tuple[T, ...], amount: int, *, fill: T | int = 0
) -> list[T | int] | tuple[T | int, ...]:
    """Shift right, filling vacated positions with ``fill``.

    EXAMPLES::

        >>> shift_right([1, 2, 3], 1)
        [0, 1, 2]
    """

    _validate(sequence, amount)
    if amount > len(sequence):
        raise ValueError("amount must not exceed the sequence length")
    if amount == 0:
        return list(sequence) if isinstance(sequence, list) else tuple(sequence)
    shifted = [fill] * amount + list(sequence[:-amount])
    return shifted if isinstance(sequence, list) else tuple(shifted)


@overload
def shift_left(sequence: list[T], amount: int, *, fill: T | int = 0) -> list[T | int]: ...


@overload
def shift_left(
    sequence: tuple[T, ...], amount: int, *, fill: T | int = 0
) -> tuple[T | int, ...]: ...


def shift_left(
    sequence: list[T] | tuple[T, ...], amount: int, *, fill: T | int = 0
) -> list[T | int] | tuple[T | int, ...]:
    """Shift left, filling vacated positions with ``fill``.

    EXAMPLES::

        >>> shift_left((1, 2, 3), 1)
        (2, 3, 0)
    """

    _validate(sequence, amount)
    if amount > len(sequence):
        raise ValueError("amount must not exceed the sequence length")
    if amount == 0:
        return list(sequence) if isinstance(sequence, list) else tuple(sequence)
    shifted = list(sequence[amount:]) + [fill] * amount
    return shifted if isinstance(sequence, list) else tuple(shifted)
