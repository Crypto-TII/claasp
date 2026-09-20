"""Xoodoo realization with explicit invertible round operations."""

from claasp.primitives.permutations.xoodoo.sbox import XoodooSbox


class XoodooInvertible(XoodooSbox):
    """A forward Xoodoo graph whose round components are individually invertible.

    EXAMPLES::

        >>> primitive = XoodooInvertible()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x89d5d88da963fcbf', 384)
    """


__all__ = ["XoodooInvertible"]
