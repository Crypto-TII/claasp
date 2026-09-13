"""Descriptions and artifacts for produced representations."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Representation:
    """A named representation format and its media type."""

    name: str
    media_type: str

    def __post_init__(self) -> None:
        if not self.name or not self.media_type:
            raise ValueError("representation name and media_type must not be empty")


@dataclass(frozen=True, slots=True)
class Artifact:
    """A concrete instance of a representation with provenance."""

    representation: Representation
    payload: object
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.representation, Representation):
            raise TypeError("representation must be a Representation")
        if any(not isinstance(item, str) or not item for item in self.provenance):
            raise ValueError("artifact provenance entries must be non-empty strings")
