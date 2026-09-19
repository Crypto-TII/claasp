"""Fixed-width integer and word-encoding helpers."""

from collections.abc import Iterable


def coerce_exact_int(value: object, parameter_name: str) -> int:
    """Return ``value`` as an integer without accepting lossy coercions.

    Booleans and numeric strings are deliberately rejected even though
    :class:`int` accepts them.

    EXAMPLES::

    >>> from claasp_next.utils import coerce_exact_int
    >>> coerce_exact_int(5.0, "rounds")
    5
    >>> coerce_exact_int(True, "rounds")
    Traceback (most recent call last):
    ...
    ValueError: rounds must be an integer
    """

    if isinstance(value, (bool, str, bytes, bytearray)):
        raise ValueError(f"{parameter_name} must be an integer")
    try:
        coerced = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"{parameter_name} must be an integer") from error
    if coerced != value:
        raise ValueError(f"{parameter_name} must be an integer")
    return coerced


def bitmask(width: int) -> int:
    """Return an integer with its low ``width`` bits set.

    EXAMPLES::

    >>> from claasp_next.utils import bitmask
    >>> hex(bitmask(32))
    '0xffffffff'
    """

    width = coerce_exact_int(width, "width")
    if width < 0:
        raise ValueError("width must be non-negative")
    return (1 << width) - 1


def bits_little_endian(value: int, width: int) -> tuple[int, ...]:
    """Return the low ``width`` bits from least to most significant.

    EXAMPLES::

        >>> bits_little_endian(0b1010, 4)
        (0, 1, 0, 1)
    """

    width = coerce_exact_int(width, "width")
    if width < 0:
        raise ValueError("width must be non-negative")
    value = coerce_exact_int(value, "value")
    if value < 0 or value > bitmask(width):
        raise ValueError(f"value must fit in {width} bits")
    return tuple((value >> position) & 1 for position in range(width))


def int_to_words(
    value: int, word_width: int, total_width: int, *, byteorder: str = "big"
) -> tuple[int, ...]:
    """Split a fixed-width integer into equally sized words.

    EXAMPLES::

        >>> int_to_words(0x1234, 8, 16)
        (18, 52)
    """

    word_width = coerce_exact_int(word_width, "word_width")
    total_width = coerce_exact_int(total_width, "total_width")
    value = coerce_exact_int(value, "value")
    if word_width <= 0 or total_width < 0 or total_width % word_width:
        raise ValueError("total_width must be a non-negative multiple of word_width")
    if value < 0 or value > bitmask(total_width):
        raise ValueError(f"value must fit in {total_width} bits")
    if byteorder not in {"big", "little"}:
        raise ValueError("byteorder must be 'big' or 'little'")
    words = tuple(
        (value >> offset) & bitmask(word_width) for offset in range(0, total_width, word_width)
    )
    return tuple(reversed(words)) if byteorder == "big" else words


def words_to_int(words: Iterable[int], word_width: int, *, byteorder: str = "big") -> int:
    """Pack equally sized words into one integer.

    EXAMPLES::

        >>> hex(words_to_int((0x12, 0x34), 8))
        '0x1234'
    """

    word_width = coerce_exact_int(word_width, "word_width")
    if word_width <= 0:
        raise ValueError("word_width must be positive")
    if byteorder not in {"big", "little"}:
        raise ValueError("byteorder must be 'big' or 'little'")
    normalized = tuple(coerce_exact_int(word, "word") for word in words)
    if any(word < 0 or word > bitmask(word_width) for word in normalized):
        raise ValueError(f"every word must fit in {word_width} bits")
    ordered = normalized if byteorder == "big" else tuple(reversed(normalized))
    value = 0
    for word in ordered:
        value = (value << word_width) | word
    return value


def int_to_bytes(value: int, width: int, *, byteorder: str = "big") -> bytes:
    """Encode an integer whose declared width is a whole number of bytes.

    EXAMPLES::

        >>> int_to_bytes(0x1234, 16)
        b'\\x124'
    """

    width = coerce_exact_int(width, "width")
    if width < 0 or width % 8:
        raise ValueError("width must be a non-negative multiple of 8")
    value = coerce_exact_int(value, "value")
    if value < 0 or value > bitmask(width):
        raise ValueError(f"value must fit in {width} bits")
    if byteorder not in {"big", "little"}:
        raise ValueError("byteorder must be 'big' or 'little'")
    return value.to_bytes(width // 8, byteorder)


def bytes_to_int(data: bytes | bytearray, *, byteorder: str = "big") -> int:
    """Decode unsigned bytes using an explicit byte order.

    EXAMPLES::

        >>> hex(bytes_to_int(b'\\x12\\x34'))
        '0x1234'
    """

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    if byteorder not in {"big", "little"}:
        raise ValueError("byteorder must be 'big' or 'little'")
    return int.from_bytes(data, byteorder, signed=False)


def rotate_left(value: int, amount: int, width: int) -> int:
    """Rotate the low ``width`` bits of ``value`` to the left.

    EXAMPLES::

        >>> from claasp_next.utils import rotate_left
        >>> hex(rotate_left(0x81, 1, 8))
        '0x3'
    """

    if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
        raise ValueError("width must be a positive integer")
    if not isinstance(amount, int) or isinstance(amount, bool):
        raise TypeError("amount must be an integer")
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << width:
        raise ValueError(f"value must be an integer in range(2^{width})")
    amount %= width
    mask = (1 << width) - 1
    return ((value << amount) | (value >> ((width - amount) % width))) & mask


def rotate_right(value: int, amount: int, width: int) -> int:
    """Rotate the low ``width`` bits of ``value`` to the right.

    EXAMPLES::

        >>> hex(rotate_right(0x81, 1, 8))
        '0xc0'
    """

    if not isinstance(amount, int) or isinstance(amount, bool):
        raise TypeError("amount must be an integer")
    return rotate_left(value, -amount, width)
