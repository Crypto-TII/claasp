"""Sage-independent typed graph definitions."""

from claasp._catalogue_metadata import _entry
from claasp.graph.binding import BindingKind, ValueBinding
from claasp.graph.component import Component
from claasp.graph.composite import (
    CompositeBuilder,
    CompositeDefinition,
    CompositeInstance,
    CompositeOutputs,
)
from claasp.graph.metadata import (
    InputVisibility,
    PrimitiveInput,
    PrimitiveKind,
    public_input,
    secret_input,
)
from claasp.graph.primitive import (
    Primitive,
    PrimitiveBuilder,
    PrimitiveDetails,
    PrimitiveEditor,
    PrimitiveGraph,
    PrimitiveInputDetails,
    PublishedValues,
)
from claasp.graph.propagation import GraphPropagation, PropagationResult
from claasp.graph.realization import (
    AmbiguousRealizationError,
    RealizationDescriptor,
    RealizationMaturity,
    RealizationSelectionError,
    RealizationSelectionPolicy,
    UnsupportedRealizationError,
    normalize_realization_contract,
    select_realization,
)
from claasp.graph.round import Round
from claasp.graph.unit_array import Selection, UnitArray, UnitArrayLike, as_selection
from claasp.graph.unit_array_type import BitWord, UnitArrayType

__all__ = [
    "AmbiguousRealizationError",
    "UnitArrayType",
    "BindingKind",
    "GraphPropagation",
    "PropagationResult",
    "BitWord",
    "Component",
    "CompositeBuilder",
    "CompositeDefinition",
    "CompositeInstance",
    "CompositeOutputs",
    "InputVisibility",
    "UnitArray",
    "UnitArrayLike",
    "Primitive",
    "PrimitiveBuilder",
    "PrimitiveDetails",
    "PrimitiveEditor",
    "PrimitiveGraph",
    "PrimitiveInput",
    "PrimitiveInputDetails",
    "PrimitiveKind",
    "PublishedValues",
    "RealizationDescriptor",
    "RealizationMaturity",
    "RealizationSelectionError",
    "RealizationSelectionPolicy",
    "Round",
    "Selection",
    "UnsupportedRealizationError",
    "ValueBinding",
    "as_selection",
    "normalize_realization_contract",
    "public_input",
    "secret_input",
    "select_realization",
]


__catalogue__ = (
    _entry(
        "representation",
        Primitive,
        name="concrete_execution",
        kind="execution",
        components=(
            "Add",
            "BinaryAffineMap",
            "BitVectorSBox",
            "BitwiseAnd",
            "BitwiseNot",
            "BitwiseOr",
            "Constant",
            "FeedbackRegister",
            "IDEAMultiply",
            "Identity",
            "LinearMap",
            "ModularAdd",
            "ModularMultiply",
            "ModularSubtract",
            "Multiply",
            "Permutation",
            "Power",
            "Rotate",
            "SBox",
            "Shift",
            "VariableRotate",
            "VariableShift",
            "Xor",
        ),
        domains=("BinaryExtensionField", "Bit", "PrimeField", "Word"),
        drivers=("python_batch", "python_scalar", "python_transposed_batch"),
        scope="generic_graph",
    ),
)
