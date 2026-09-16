"""SimeckSbox typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class SimeckSbox(CatalogueGraphPrimitive):
    """Construct SimeckSbox from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "simeck_sbox", args, parameters)
        super().__init__(specification)


__all__ = ["SimeckSbox"]
