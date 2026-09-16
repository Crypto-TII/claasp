"""MD5 typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class MD5(CatalogueGraphPrimitive):
    """Construct MD5 from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("functions", "md5", args, parameters)
        super().__init__(specification)


__all__ = ["MD5"]
