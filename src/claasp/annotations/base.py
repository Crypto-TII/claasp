"""Immutable annotations attached to typed primitive graph sources."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum

from claasp.graph import Primitive
from claasp.semantics import SemanticType


class AnnotationRole(str, Enum):
    """Identify the kind of graph source carrying an annotation.

    EXAMPLES::

        >>> AnnotationRole.COMPONENT.value
        'component'
    """

    INPUT = "input"
    COMPONENT = "component"
    OUTPUT = "output"


@dataclass(frozen=True, slots=True)
class AnnotationEntry:
    """Bind one named graph source to a semantics-specific payload.

    EXAMPLES::

        >>> AnnotationEntry("plaintext", AnnotationRole.INPUT, 3).value
        3
    """

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
    """Validate an immutable assignment of information to graph sources.

    EXAMPLES::

        >>> from claasp import Bit, Primitive, ValueType
        >>> from claasp.semantics import CONCRETE
        >>> primitive = Primitive("identity", {"state": ValueType(Bit(), (1,))})
        >>> annotation = GraphAnnotation.from_values(primitive, CONCRETE, {"state": 1}, output=1)
        >>> (annotation.value_of("state"), annotation.realization_identity)
        (1, 'identity:default')
    """

    primitive: Primitive
    semantics: SemanticType
    entries: tuple[AnnotationEntry, ...]

    @property
    def realization(self):
        """Realization descriptor of the graph to which values are attached."""

        return self.primitive.realization

    @property
    def realization_identity(self) -> str:
        """Return the annotated graph's stable realization identity."""

        return self.primitive.realization_identity

    def __init__(
        self,
        primitive: Primitive,
        semantics: SemanticType,
        entries: Iterable[AnnotationEntry],
    ) -> None:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        if not isinstance(semantics, SemanticType):
            raise TypeError("semantics must be a SemanticType")
        frozen = tuple(entries)
        identifiers = tuple((entry.role, entry.source_id) for entry in frozen)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("each graph source and role may be annotated only once")
        inputs = set(primitive.input_ports)
        components = {component.component_id for component in primitive.components}
        for entry in frozen:
            if entry.role is AnnotationRole.INPUT and entry.source_id not in inputs:
                raise ValueError(f"unknown primitive input {entry.source_id!r}")
            if entry.role is AnnotationRole.COMPONENT and entry.source_id not in components:
                raise ValueError(f"unknown primitive component {entry.source_id!r}")
            if entry.role is AnnotationRole.OUTPUT and entry.source_id != "primitive_output":
                raise ValueError("the graph output annotation is named 'primitive_output'")
        object.__setattr__(self, "primitive", primitive)
        object.__setattr__(self, "semantics", semantics)
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
        primitive: Primitive,
        semantics: SemanticType,
        values: Mapping[str, object],
        *,
        output: object | None = None,
    ) -> "GraphAnnotation":
        """Build entries from familiar source-ID mappings."""

        input_names = set(primitive.input_ports)
        entries = [
            AnnotationEntry(
                source_id,
                AnnotationRole.INPUT if source_id in input_names else AnnotationRole.COMPONENT,
                value,
            )
            for source_id, value in values.items()
        ]
        if output is not None:
            entries.append(AnnotationEntry("primitive_output", AnnotationRole.OUTPUT, output))
        return cls(primitive, semantics, entries)
