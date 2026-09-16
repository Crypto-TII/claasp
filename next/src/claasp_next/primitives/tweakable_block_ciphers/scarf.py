"""SCARF typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class SCARF(CatalogueGraphPrimitive):
    """Construct SCARF from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("tweakable_block_ciphers", "scarf", args, parameters)
        super().__init__(specification)


__all__ = ["SCARF"]
