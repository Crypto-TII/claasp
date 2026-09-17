"""Xoodoo represented with explicit invertible round operations."""

from claasp_next.primitives.permutations.xoodoo_sbox import XoodooSbox


class XoodooInvertible(XoodooSbox):
    """A forward Xoodoo graph whose round components are individually invertible."""

__all__ = ["XoodooInvertible"]
