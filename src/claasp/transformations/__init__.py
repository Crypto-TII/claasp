"""Immutable, validated transformations of typed primitive graphs."""

from claasp.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
    TransformationResult,
)
from claasp.transformations.editing import (
    inline_reorderings,
    prune_orphans,
    remove_key_schedule,
)
from claasp.transformations.inverse_equivalents import (
    DEFAULT_PRIMITIVE_INVERSE_EQUIVALENTS,
    PrimitiveInverseEquivalent,
)
from claasp.transformations.inverse_rules import (
    DEFAULT_INVERSE_REGISTRY,
    ComponentInverseRegistry,
    ComponentInverseSemantics,
    invert_component,
)
from claasp.transformations.inversion import invert_primitive, partial_inverse
from claasp.transformations.paired import (
    PairedTransformationResult,
    paired_xor_primitive,
)
from claasp.transformations.slicing import (
    DependencySplit,
    reduce_rounds,
    slice_primitive,
    slice_rounds,
    split_dependencies,
)
from claasp.transformations.traversal import (
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
