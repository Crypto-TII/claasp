"""SiphashMAC typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class SiphashMAC(CatalogueGraphPrimitive):
    """Construct SiphashMAC from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_functions", "siphash", args, parameters)
        super().__init__(specification)


__all__ = ["SiphashMAC"]
