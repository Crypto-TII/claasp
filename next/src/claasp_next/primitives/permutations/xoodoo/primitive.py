"""Xoodoo typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Xoodoo(CatalogueGraphPrimitive):
    """Construct Xoodoo from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "xoodoo", args, parameters)
        super().__init__(specification)


__all__ = ["Xoodoo"]
