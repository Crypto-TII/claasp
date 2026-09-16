"""Norx typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Norx(CatalogueGraphPrimitive):
    """Construct Norx from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "norx", args, parameters)
        super().__init__(specification)


__all__ = ["Norx"]
