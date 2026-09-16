"""PrinceV2 typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class PrinceV2(CatalogueGraphPrimitive):
    """Construct PrinceV2 from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "prince_v2", args, parameters)
        super().__init__(specification)


__all__ = ["PrinceV2"]
