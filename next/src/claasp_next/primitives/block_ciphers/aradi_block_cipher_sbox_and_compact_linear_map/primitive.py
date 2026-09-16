"""Aradi compact-linear-map typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class AradiSBoxCompactLinearMap(CatalogueGraphPrimitive):
    """Construct the compact-linear-map realization of Aradi."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "aradi_block_cipher_sbox_and_compact_linear_map", args, parameters)
        super().__init__(specification)


__all__ = ["AradiSBoxCompactLinearMap"]
