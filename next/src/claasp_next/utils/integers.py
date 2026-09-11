"""Fixed-width integer helpers."""


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
