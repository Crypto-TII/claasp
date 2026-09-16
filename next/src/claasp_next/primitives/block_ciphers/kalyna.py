"""Kalyna typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Kalyna(CatalogueGraphPrimitive):
    """Construct Kalyna from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "kalyna", args, parameters)
        super().__init__(specification)


__all__ = ["Kalyna"]
