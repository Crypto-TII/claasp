"""Canonical conversions for bit-oriented graph boundaries."""


def bits_from_int(value: int, width: int) -> tuple[int, ...]:
    """Return *width* bits in most-significant-bit-first order.

    EXAMPLES::

        >>> bits_from_int(0xA, 4)
        (1, 0, 1, 0)
    """

    if not isinstance(width, int) or isinstance(width, bool):
        raise TypeError("width must be an integer")
    if width <= 0:
        raise ValueError("width must be positive")
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("value must be an integer")
    if value < 0 or value >= (1 << width):
        raise ValueError(f"value must fit in {width} bits")
    return tuple((value >> position) & 1 for position in range(width - 1, -1, -1))


def int_from_bits(bits: tuple[int, ...]) -> int:
    """Decode a non-empty, most-significant-bit-first bit tuple.

    EXAMPLES::

        >>> int_from_bits((1, 0, 1, 0))
        10
    """

    if not isinstance(bits, tuple):
        raise TypeError("bits must be a tuple")
    if not bits:
        raise ValueError("bits must not be empty")
    value = 0
    for bit in bits:
        if not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1):
            raise ValueError("bits must contain only integer zeroes and ones")
        value = (value << 1) | bit
    return value
