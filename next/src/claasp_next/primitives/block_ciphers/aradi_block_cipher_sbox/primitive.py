"""Aradi S-box typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class AradiSBox(CatalogueGraphPrimitive):
    """Construct the S-box realization of Aradi from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "aradi_block_cipher_sbox", args, parameters)
        super().__init__(specification)


__all__ = ["AradiSBox"]
