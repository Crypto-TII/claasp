"""Immutable annotations attached to typed cipher graph sources."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum

from claasp_next.core import Cipher
from claasp_next.interpretations import Interpretation


class AnnotationRole(str, Enum):
    """Role of an annotated source in the cipher graph."""

    INPUT = "input"
    COMPONENT = "component"
    OUTPUT = "output"


@dataclass(frozen=True, slots=True)
class AnnotationEntry:
    """One named graph source and its interpretation-specific payload."""

    source_id: str
    role: AnnotationRole
    value: object

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("annotation source_id must not be empty")
        if not isinstance(self.role, AnnotationRole):
            raise TypeError("annotation role must be an AnnotationRole")


@dataclass(frozen=True, slots=True, init=False)
class GraphAnnotation:
    """An immutable, validated assignment of information to graph sources."""

    cipher: Cipher
    interpretation: Interpretation
    entries: tuple[AnnotationEntry, ...]

    def __init__(
        self,
        cipher: Cipher,
        interpretation: Interpretation,
        entries: Iterable[AnnotationEntry],
    ) -> None:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        if not isinstance(interpretation, Interpretation):
            raise TypeError("interpretation must be an Interpretation")
        frozen = tuple(entries)
        identifiers = tuple(entry.source_id for entry in frozen)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("each graph source may be annotated only once")
        inputs = set(cipher.inputs)
        components = {component.component_id for component in cipher.components}
        for entry in frozen:
            if entry.role is AnnotationRole.INPUT and entry.source_id not in inputs:
                raise ValueError(f"unknown cipher input {entry.source_id!r}")
            if entry.role is AnnotationRole.COMPONENT and entry.source_id not in components:
                raise ValueError(f"unknown cipher component {entry.source_id!r}")
            if entry.role is AnnotationRole.OUTPUT and entry.source_id != "cipher_output":
                raise ValueError("the graph output annotation is named 'cipher_output'")
        object.__setattr__(self, "cipher", cipher)
        object.__setattr__(self, "interpretation", interpretation)
        object.__setattr__(self, "entries", frozen)

    def value_of(self, source_id: str) -> object:
        """Return the payload for ``source_id`` or raise a descriptive error."""

        for entry in self.entries:
            if entry.source_id == source_id:
                return entry.value
        raise KeyError(f"graph source {source_id!r} is not annotated")

    @classmethod
    def from_values(
        cls,
        cipher: Cipher,
        interpretation: Interpretation,
        values: Mapping[str, object],
        *,
        output: object | None = None,
    ) -> "GraphAnnotation":
        """Build entries from familiar source-ID mappings."""

        input_names = set(cipher.inputs)
        entries = [
            AnnotationEntry(
                source_id,
                AnnotationRole.INPUT if source_id in input_names else AnnotationRole.COMPONENT,
                value,
            )
            for source_id, value in values.items()
        ]
        if output is not None:
            entries.append(AnnotationEntry("cipher_output", AnnotationRole.OUTPUT, output))
        return cls(cipher, interpretation, entries)
