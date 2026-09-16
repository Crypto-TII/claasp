"""GastonSboxTheta typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class GastonSboxTheta(CatalogueGraphPrimitive):
    """Construct GastonSboxTheta from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "gaston_sbox_theta", args, parameters)
        super().__init__(specification)


__all__ = ["GastonSboxTheta"]
