"""Xoodoo realization with explicit invertible round operations."""

from claasp_next.primitives.permutations.xoodoo.sbox import XoodooSbox


class XoodooInvertible(XoodooSbox):
    """A forward Xoodoo graph whose round components are individually invertible."""

__all__ = ["XoodooInvertible"]
