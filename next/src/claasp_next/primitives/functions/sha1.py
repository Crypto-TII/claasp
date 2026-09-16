"""SHA1 typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class SHA1(CatalogueGraphPrimitive):
    """Construct SHA1 from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("functions", "sha1", args, parameters)
        super().__init__(specification)


__all__ = ["SHA1"]
