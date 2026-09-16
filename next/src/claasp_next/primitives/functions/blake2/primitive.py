"""Blake2 typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class Blake2(CatalogueGraphPrimitive):
    """Construct Blake2 from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("functions", "blake2", args, parameters)
        super().__init__(specification)


__all__ = ["Blake2"]
