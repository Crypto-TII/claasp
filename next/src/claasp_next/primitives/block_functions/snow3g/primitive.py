"""Snow3G typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Snow3G(CatalogueGraphPrimitive):
    """Construct Snow3G from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_functions", "snow3g", args, parameters)
        super().__init__(specification)


__all__ = ["Snow3G"]
