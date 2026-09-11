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


def units_from_int(value: int, unit_width: int, count: int) -> tuple[int, ...]:
    """Split an integer into ``count`` MSB-first fixed-width units."""

    if not isinstance(unit_width, int) or isinstance(unit_width, bool) or unit_width <= 0:
        raise ValueError("unit_width must be a positive integer")
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        raise ValueError("count must be a positive integer")
    width = unit_width * count
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("value must be an integer")
    if not 0 <= value < 1 << width:
        raise ValueError(f"value must fit in {width} bits")
    mask = (1 << unit_width) - 1
    return tuple(
        (value >> (unit_width * (count - position - 1))) & mask
        for position in range(count)
    )


def int_from_units(units: tuple[int, ...], unit_width: int) -> int:
    """Join non-empty MSB-first fixed-width units into one integer."""

    if not isinstance(units, tuple) or not units:
        raise ValueError("units must be a non-empty tuple")
    if not isinstance(unit_width, int) or isinstance(unit_width, bool) or unit_width <= 0:
        raise ValueError("unit_width must be a positive integer")
    limit = 1 << unit_width
    value = 0
    for unit in units:
        if not isinstance(unit, int) or isinstance(unit, bool) or not 0 <= unit < limit:
            raise ValueError(f"units must contain integers in range(2^{unit_width})")
        value = (value << unit_width) | unit
    return value
