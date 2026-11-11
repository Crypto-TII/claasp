"""Xoodoo realization with explicit invertible round operations."""

from claasp._catalogue_metadata import _entry
from claasp.primitives.permutations.xoodoo.sbox import XoodooSbox


class XoodooInvertible(XoodooSbox):
    """A forward Xoodoo graph whose round components are individually invertible.

    EXAMPLES::

        >>> primitive = XoodooInvertible()
        >>> inputs = {name: 0 for name in primitive.graph.input_arrays}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x89d5d88da963fcbf', 384)
    """


__all__ = ["XoodooInvertible"]


__catalogue__ = (_entry("primitive", XoodooInvertible, labels=("exact_alias",)),)
