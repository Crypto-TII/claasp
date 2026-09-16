"""QARMAv2MixColumn typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class QARMAv2MixColumn(CatalogueGraphPrimitive):
    """Construct QARMAv2MixColumn from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("tweakable_block_ciphers", "qarmav2_with_mixcolumn", args, parameters)
        super().__init__(specification)


__all__ = ["QARMAv2MixColumn"]
