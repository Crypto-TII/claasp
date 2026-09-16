"""DESExactKeyLength typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class DESExactKeyLength(CatalogueGraphPrimitive):
    """Construct DESExactKeyLength from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("block_ciphers", "des_exact_key_length", args, parameters)
        super().__init__(specification)


__all__ = ["DESExactKeyLength"]
