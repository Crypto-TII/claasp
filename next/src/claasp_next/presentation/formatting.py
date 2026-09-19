"""Deterministic, locale-independent formatting for report cells."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from math import isfinite
from typing import SupportsFloat


class ValueKind(str, Enum):
    """Semantic formatting kind for one table cell.

    EXAMPLES::

        >>> tuple(member.value for member in ValueKind)
        ('text', 'integer', 'hexadecimal', 'bit_vector', 'word_vector', 'probability', 'correlation', 'weight', 'boolean')
    """

    TEXT = "text"
    INTEGER = "integer"
    HEXADECIMAL = "hexadecimal"
    BIT_VECTOR = "bit_vector"
    WORD_VECTOR = "word_vector"
    PROBABILITY = "probability"
    CORRELATION = "correlation"
    WEIGHT = "weight"
    BOOLEAN = "boolean"


@dataclass(frozen=True, slots=True)
class FormatSpec:
    """Formatting request independent of any renderer.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (FormatSpec.__dataclass_params__.frozen, tuple(field.name for field in fields(FormatSpec)))
        (True, ('kind', 'precision', 'bit_width', 'word_width'))
    """

    kind: ValueKind = ValueKind.TEXT
    precision: int = 6
    bit_width: int | None = None
    word_width: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ValueKind):
            object.__setattr__(self, "kind", ValueKind(self.kind))
        if (
            not isinstance(self.precision, int)
            or isinstance(self.precision, bool)
            or self.precision < 1
        ):
            raise ValueError("precision must be a positive integer")
        for name, value in (("bit_width", self.bit_width), ("word_width", self.word_width)):
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value <= 0
            ):
                raise ValueError(f"{name} must be a positive integer or None")


def _number(value: object, precision: int) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("numeric cells require an integer or float")
    if isinstance(value, float) and not isfinite(value):
        return "infinity" if value > 0 else "-infinity"
    return format(value, f".{precision}g")


def format_value(value: object, spec: FormatSpec = FormatSpec()) -> str:
    """Format one typed value without locale or object-repr dependence.

    EXAMPLES::

        >>> format_value(10, FormatSpec(ValueKind.HEXADECIMAL, bit_width=8))
        '0x0a'
        >>> format_value((1, 0, 1), FormatSpec(ValueKind.BIT_VECTOR))
        '0b101'
        >>> format_value(0.125, FormatSpec(ValueKind.PROBABILITY))
        '0.125'
    """

    kind = spec.kind
    if value is None:
        return "—"
    if kind is ValueKind.TEXT:
        if not isinstance(value, str):
            raise TypeError("text cells require strings")
        return value
    if kind is ValueKind.INTEGER:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("integer cells require integers")
        return str(value)
    if kind is ValueKind.HEXADECIMAL:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TypeError("hexadecimal cells require non-negative integers")
        digits = 1 if spec.bit_width is None else (spec.bit_width + 3) // 4
        if spec.bit_width is not None and value >= 1 << spec.bit_width:
            raise ValueError("hexadecimal value does not fit bit_width")
        return f"0x{value:0{digits}x}"
    if kind is ValueKind.BIT_VECTOR:
        if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
            raise TypeError("bit vectors require an iterable of bits")
        bits: tuple[object, ...] = tuple(value)
        if any(bit not in (0, 1) for bit in bits):
            raise ValueError("bit vectors contain only zero and one")
        if spec.bit_width is not None and len(bits) != spec.bit_width:
            raise ValueError("bit vector length does not match bit_width")
        return "0b" + "".join(str(bit) for bit in bits)
    if kind is ValueKind.WORD_VECTOR:
        if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
            raise TypeError("word vectors require an iterable of words")
        words: tuple[object, ...] = tuple(value)
        if spec.word_width is None:
            raise ValueError("word vectors require word_width")
        item_spec = FormatSpec(ValueKind.HEXADECIMAL, bit_width=spec.word_width)
        return "[" + ", ".join(format_value(word, item_spec) for word in words) + "]"
    if kind in {ValueKind.PROBABILITY, ValueKind.CORRELATION}:
        if not isinstance(value, SupportsFloat):
            raise TypeError(f"{kind.value} cells require real numbers")
        number = float(value)
        if not -1.0 <= number <= 1.0:
            raise ValueError(f"{kind.value} must be between -1 and 1")
        rendered = _number(number, spec.precision)
        return ("+" + rendered) if kind is ValueKind.CORRELATION and number >= 0 else rendered
    if kind is ValueKind.WEIGHT:
        if not isinstance(value, SupportsFloat):
            raise TypeError("weight cells require real numbers")
        number = float(value)
        if number < 0:
            raise ValueError("weights must be non-negative")
        return _number(number, spec.precision)
    if kind is ValueKind.BOOLEAN:
        if not isinstance(value, bool):
            raise TypeError("Boolean cells require bool values")
        return "true" if value else "false"
    raise ValueError(f"unsupported value kind {kind!r}")
