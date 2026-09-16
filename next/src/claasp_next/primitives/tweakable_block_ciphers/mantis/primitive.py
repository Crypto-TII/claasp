"""Mantis typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Mantis(CatalogueGraphPrimitive):
    """Construct Mantis from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("tweakable_block_ciphers", "mantis", args, parameters)
        super().__init__(specification)


__all__ = ["Mantis"]
