"""Ascon typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Ascon(CatalogueGraphPrimitive):
    """Construct Ascon from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "ascon", args, parameters)
        super().__init__(specification)


__all__ = ["Ascon"]
