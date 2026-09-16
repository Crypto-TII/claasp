"""A51 typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class A51(CatalogueGraphPrimitive):
    """Construct A51 from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_functions", "a5_1", args, parameters)
        super().__init__(specification)


__all__ = ["A51"]
