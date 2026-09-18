"""Public contracts shared by immutable graph transformations."""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from collections.abc import Mapping

from claasp_next.graph import Primitive
from claasp_next.provenance import TransformationRecord


class TransformationFailureReason(str, Enum):
    """Stable reasons why a graph transformation cannot proceed.

    EXAMPLES::

        >>> TransformationFailureReason.MISSING_AUXILIARY_VALUE.value
        'missing_auxiliary_value'
    """

    UNSUPPORTED_COMPONENT = "unsupported_component"
    INFORMATION_LOSS = "information_loss"
    MULTIPLE_PREDECESSORS = "multiple_predecessors"
    MISSING_AUXILIARY_VALUE = "missing_auxiliary_value"
    AMBIGUOUS_BOUNDARY = "ambiguous_boundary"
    DISCONNECTED_DEPENDENCY = "disconnected_dependency"
    INVALID_GRAPH = "invalid_graph"


class TransformationError(ValueError):
    """A typed transformation failure with machine-readable context.

    EXAMPLES::

        >>> error = TransformationError(
        ...     TransformationFailureReason.AMBIGUOUS_BOUNDARY,
        ...     "choose one graph source", source_ids=("left", "right"),
        ... )
        >>> error.reason.value
        'ambiguous_boundary'
        >>> str(error)
        'ambiguous_boundary: choose one graph source [left, right]'
    """

    def __init__(
        self,
        reason: TransformationFailureReason | str,
        message: str,
        *,
        source_ids: tuple[str, ...] = (),
    ) -> None:
        self.reason = (
            reason if isinstance(reason, TransformationFailureReason)
            else TransformationFailureReason(reason)
        )
        if not isinstance(message, str) or not message:
            raise ValueError("transformation error message must be non-empty")
        if not isinstance(source_ids, tuple) or any(
            not isinstance(item, str) or not item for item in source_ids
        ):
            raise TypeError("transformation error source_ids must be non-empty strings")
        self.source_ids = source_ids
        suffix = "" if not source_ids else f" [{', '.join(source_ids)}]"
        super().__init__(f"{self.reason.value}: {message}{suffix}")


@dataclass(frozen=True, slots=True)
class TransformationResult:
    """A validated transformed primitive and explicit source correspondence.

    EXAMPLES::

        >>> from claasp_next.primitives import Speck
        >>> primitive = Speck(number_of_rounds=1)
        >>> result = TransformationResult(primitive, (("plaintext", "plaintext"),))
        >>> result.source_map["plaintext"]
        'plaintext'
    """

    primitive: Primitive
    sources: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.primitive, Primitive):
            raise TypeError("transformation result must contain a Primitive")
        if not isinstance(self.sources, tuple) or any(
            not isinstance(item, tuple) or len(item) != 2
            or not all(isinstance(value, str) and value for value in item)
            for item in self.sources
        ):
            raise TypeError("transformation sources must be non-empty string pairs")

    @property
    def source_map(self) -> Mapping[str, str]:
        """Return an immutable old-to-new graph-source map."""

        return MappingProxyType(dict(self.sources))


def record_transformation(
    primitive: Primitive,
    operation: str,
    parameters: tuple[tuple[str, str], ...] = (),
) -> Primitive:
    """Append transformation provenance to an already reconstructed graph."""

    record = TransformationRecord(operation, parameters, primitive.realization_identity)
    object.__setattr__(
        primitive,
        "_transformation_provenance",
        (*primitive.transformation_provenance, record),
    )
    return primitive


__all__ = [
    "TransformationError", "TransformationFailureReason", "TransformationResult",
]
