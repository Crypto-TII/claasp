"""Splight typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Splight(CatalogueGraphPrimitive):
    """Construct Splight from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "splight", args, parameters)
        super().__init__(specification)


__all__ = ["Splight"]
