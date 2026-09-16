"""Keccak represented with explicit invertible round operations."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class KeccakInvertible(CatalogueGraphPrimitive):
    """A forward Keccak graph whose round components are individually invertible."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "keccak_sbox", args, parameters)
        super().__init__(specification, family_name="keccak")


__all__ = ["KeccakInvertible"]
