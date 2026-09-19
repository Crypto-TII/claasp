"""Immutable, validated transformations of typed primitive graphs."""

from claasp_next.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
    TransformationResult,
)
from claasp_next.transformations.editing import (
    inline_reorderings,
    prune_orphans,
    remove_key_schedule,
)
from claasp_next.transformations.inverse_equivalents import (
    DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS,
    PrimitiveInverseEquivalent,
)
from claasp_next.transformations.inverse_rules import (
    DEFAULT_INVERSE_REGISTRY,
    ComponentInverseRegistry,
    ComponentInverseSemantics,
    invert_component,
)
from claasp_next.transformations.inversion import invert_primitive, partial_inverse
from claasp_next.transformations.paired import (
    PairedTransformationResult,
    paired_xor_primitive,
)
from claasp_next.transformations.slicing import (
    DependencySplit,
    reduce_rounds,
    slice_primitive,
    slice_rounds,
    split_dependencies,
)
from claasp_next.transformations.traversal import (
    DependencyIndex,
    GraphSource,
    GraphSourceKind,
)

__all__ = [
    "DEFAULT_INVERSE_REGISTRY",
    "DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS",
    "ComponentInverseRegistry",
    "ComponentInverseSemantics",
    "DependencyIndex",
    "DependencySplit",
    "GraphSource",
    "GraphSourceKind",
    "PairedTransformationResult",
    "PrimitiveInverseEquivalent",
    "TransformationError",
    "TransformationFailureReason",
    "TransformationResult",
    "inline_reorderings",
    "invert_component",
    "invert_primitive",
    "paired_xor_primitive",
    "partial_inverse",
    "prune_orphans",
    "reduce_rounds",
    "remove_key_schedule",
    "slice_primitive",
    "slice_rounds",
    "split_dependencies",
]
