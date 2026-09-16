"""Sage-independent rotation and shifting of homogeneous sequences."""

from collections.abc import Sequence
from typing import TypeVar


T = TypeVar("T")


def _validate(sequence: Sequence[T], amount: int) -> None:
    if not isinstance(sequence, (list, tuple)):
        raise TypeError("sequence must be a list or tuple")
    if not isinstance(amount, int) or isinstance(amount, bool):
        raise TypeError("amount must be an integer")
    if amount < 0:
        raise ValueError("amount must be non-negative")


def rotate_right(sequence: list[T] | tuple[T, ...], amount: int) -> list[T] | tuple[T, ...]:
    """Return a right-rotated sequence of the same concrete type.

    >>> from claasp_next.utils import rotate_sequence_right
    >>> rotate_sequence_right([1, 2, 3, 4, 5], 2)
    [4, 5, 1, 2, 3]
    """

    _validate(sequence, amount)
    if not sequence:
        return sequence
    amount %= len(sequence)
    if amount == 0:
        return sequence[:]
    return sequence[-amount:] + sequence[:-amount]


def rotate_left(sequence: list[T] | tuple[T, ...], amount: int) -> list[T] | tuple[T, ...]:
    """Return a left-rotated sequence of the same concrete type."""

    _validate(sequence, amount)
    if not sequence:
        return sequence
    return rotate_right(sequence, (-amount) % len(sequence))


def shift_right(
    sequence: list[T] | tuple[T, ...], amount: int, *, fill: T | int = 0
) -> list[T | int] | tuple[T | int, ...]:
    """Shift right, filling vacated positions with ``fill``."""

    _validate(sequence, amount)
    if amount > len(sequence):
        raise ValueError("amount must not exceed the sequence length")
    if amount == 0:
        return sequence[:]
    return type(sequence)([fill] * amount + list(sequence[:-amount]))


def shift_left(
    sequence: list[T] | tuple[T, ...], amount: int, *, fill: T | int = 0
) -> list[T | int] | tuple[T | int, ...]:
    """Shift left, filling vacated positions with ``fill``."""

    _validate(sequence, amount)
    if amount > len(sequence):
        raise ValueError("amount must not exceed the sequence length")
    if amount == 0:
        return sequence[:]
    return type(sequence)(list(sequence[amount:]) + [fill] * amount)
