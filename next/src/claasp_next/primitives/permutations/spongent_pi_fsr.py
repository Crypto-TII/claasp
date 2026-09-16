"""Spongent-pi feedback-register realization."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class SpongentPiFSR(CatalogueGraphPrimitive):
    """Spongent-pi with its counter register represented by equivalent wiring."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("permutations", "spongent_pi", args, parameters)
        super().__init__(specification, family_name="spongent_pi")


__all__ = ["SpongentPiFSR"]
