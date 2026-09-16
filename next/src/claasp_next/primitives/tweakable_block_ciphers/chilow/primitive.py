"""Chilow typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Chilow(CatalogueGraphPrimitive):
    """Construct Chilow from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("tweakable_block_ciphers", "chilow", args, parameters)
        super().__init__(specification)


__all__ = ["Chilow"]
