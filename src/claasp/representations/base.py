"""Descriptions and artifacts for produced representations."""

from dataclasses import dataclass

from claasp.provenance import ResultProvenance


@dataclass(frozen=True, slots=True)
class Representation:
    """A named representation format and its media type.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (Representation.__dataclass_params__.frozen, tuple(field.name for field in fields(Representation)))
        (True, ('name', 'media_type'))
    """

    name: str
    media_type: str

    def __post_init__(self) -> None:
        if not self.name or not self.media_type:
            raise ValueError("representation name and media_type must not be empty")


@dataclass(frozen=True, slots=True)
class Artifact:
    """A concrete instance of a representation with provenance.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (Artifact.__dataclass_params__.frozen, tuple(field.name for field in fields(Artifact)))
        (True, ('representation', 'payload', 'provenance', 'result_provenance'))
    """

    representation: Representation
    payload: object
    provenance: tuple[str, ...] = ()
    result_provenance: ResultProvenance | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.representation, Representation):
            raise TypeError("representation must be a Representation")
        if any(not isinstance(item, str) or not item for item in self.provenance):
            raise ValueError("artifact provenance entries must be non-empty strings")
        if self.result_provenance is not None and not isinstance(
            self.result_provenance, ResultProvenance
        ):
            raise TypeError("result_provenance must be ResultProvenance or None")
