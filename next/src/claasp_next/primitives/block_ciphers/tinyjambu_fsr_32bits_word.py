"""TinyJambuFSRWordBased typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class TinyJambuFSRWordBased(CatalogueGraphPrimitive):
    """Construct TinyJambuFSRWordBased from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "tinyjambu_fsr_32bits_word", args, parameters)
        super().__init__(specification)


__all__ = ["TinyJambuFSRWordBased"]
