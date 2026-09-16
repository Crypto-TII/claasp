"""Xoodoo represented with explicit invertible round operations."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class XoodooInvertible(CatalogueGraphPrimitive):
    """A forward Xoodoo graph whose round components are individually invertible."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "xoodoo_sbox", args, parameters)
        super().__init__(specification, family_name="xoodoo")


__all__ = ["XoodooInvertible"]
