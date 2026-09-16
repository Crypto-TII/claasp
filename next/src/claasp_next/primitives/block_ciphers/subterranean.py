"""Subterranean typed primitive graph."""

from enum import Enum

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_spec,
)


class Version(Enum):
    """Subterranean construction version."""

    V1 = 1
    V2 = 2


class Subterranean(CatalogueGraphPrimitive):
    """Construct Subterranean from an audited parameter set."""

    def __init__(self, number_of_rounds: int = 1, version: Version = Version.V1) -> None:
        if not isinstance(version, Version):
            raise TypeError("version must be a Subterranean Version")
        variants = {
            (Version.V1, 1): "v1_r1",
            (Version.V1, 3): "v1_r3",
            (Version.V2, 5): "v2_r5",
        }
        try:
            variant = variants[(version, number_of_rounds)]
        except KeyError as error:
            raise ValueError(f"unsupported Subterranean version/round combination: {version.name}/{number_of_rounds}") from error
        specification = load_catalogue_spec("block_ciphers", "subterranean", variant)
        super().__init__(specification)


__all__ = ["Subterranean", "Version"]
