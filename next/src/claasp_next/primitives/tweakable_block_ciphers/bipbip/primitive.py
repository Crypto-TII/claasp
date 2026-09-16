"""BipBip typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class BipBip(CatalogueGraphPrimitive):
    """Construct BipBip from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("tweakable_block_ciphers", "bipbip", args, parameters)
        super().__init__(specification)


__all__ = ["BipBip"]
