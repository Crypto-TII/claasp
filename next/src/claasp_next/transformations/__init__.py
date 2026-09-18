"""Immutable, validated transformations of typed primitive graphs."""

from claasp_next.transformations.contracts import (
    TransformationError, TransformationFailureReason, TransformationResult,
)
from claasp_next.transformations.traversal import (
    DependencyIndex, GraphSource, GraphSourceKind,
)
from claasp_next.transformations.slicing import (
    DependencySplit, reduce_rounds, slice_primitive, slice_rounds,
    split_dependencies,
)
from claasp_next.transformations.inverse_rules import (
    ComponentInverseRegistry, ComponentInverseSemantics,
    DEFAULT_INVERSE_REGISTRY, invert_component,
)

__all__ = [
    "ComponentInverseRegistry", "ComponentInverseSemantics", "DEFAULT_INVERSE_REGISTRY",
    "DependencyIndex", "DependencySplit", "GraphSource", "GraphSourceKind", "TransformationError",
    "TransformationFailureReason", "TransformationResult",
    "invert_component", "reduce_rounds", "slice_primitive", "slice_rounds", "split_dependencies",
]
