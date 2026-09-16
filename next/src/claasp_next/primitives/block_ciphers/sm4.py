"""SM4 typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class SM4(CatalogueGraphPrimitive):
    """Construct SM4 from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "sm4", args, parameters)
        super().__init__(specification)


__all__ = ["SM4"]
