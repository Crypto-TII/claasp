"""Forro typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Forro(CatalogueGraphPrimitive):
    """Construct Forro from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "forro", args, parameters)
        super().__init__(specification)


__all__ = ["Forro"]
