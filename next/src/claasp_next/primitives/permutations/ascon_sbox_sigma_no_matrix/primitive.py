"""AsconSboxSigmaNoMatrix typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class AsconSboxSigmaNoMatrix(CatalogueGraphPrimitive):
    """Construct AsconSboxSigmaNoMatrix from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "ascon_sbox_sigma_no_matrix", args, parameters)
        super().__init__(specification)


__all__ = ["AsconSboxSigmaNoMatrix"]
