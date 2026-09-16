"""A52 typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class A52(CatalogueGraphPrimitive):
    """Construct A52 from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_functions", "a5_2", args, parameters)
        super().__init__(specification)


__all__ = ["A52"]
