"""Early, contextual capability checks for deterministic impossible searches."""

from typing import NoReturn

from claasp.components import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    LinearMap,
    ModularAdd,
    ModularSubtract,
    Permutation,
    Rotate,
    SBox,
    Shift,
    Xor,
)
from claasp.graph import GraphPropagation
from claasp.unit_types import BinaryExtensionField, Bit, Word


def _require_impossible_capability(primitive, representation):
    from claasp.analysis.trail_search import TrailSearchCapabilityError

    def reject(feature) -> NoReturn:
        raise TrailSearchCapabilityError(
            f"{primitive.family_name}: {representation} impossible search cannot model {feature}. "
            "A published round boundary alone does not supply differential semantics."
        )

    for name, array_type in GraphPropagation(primitive).sources:
        if not isinstance(array_type.unit_type, (Bit, Word, BinaryExtensionField)):
            reject(f"source {name!r} with {type(array_type.unit_type).__name__} units")
    supported: tuple[type, ...] = (
        Add,
        Xor,
        ModularAdd,
        ModularSubtract,
        BitwiseAnd,
        BitwiseOr,
        BitwiseNot,
        Identity,
        Rotate,
        Permutation,
        Constant,
        SBox,
        LinearMap,
    )
    if representation == "bitwise":
        supported += (BitVectorSBox, BinaryAffineMap, Shift)
    for component in primitive.graph.components:
        description = f"component {component.component_id!r} ({type(component).__name__})"
        if not isinstance(component, supported):
            reject(description)
        if isinstance(component, ModularAdd):
            width = component.output_type.unit_type.encoded_bit_size
            if width is None or component.modulus not in (None, 1 << width):
                reject(description + ": only power-of-two modular arithmetic is modeled")
        if isinstance(component, Add) and not isinstance(
            component.output_type.unit_type, (Bit, BinaryExtensionField)
        ):
            reject(description + ": use ModularAdd for Word arithmetic")
        if isinstance(component, LinearMap) and not isinstance(
            component.output_type.unit_type, (Bit, BinaryExtensionField)
        ):
            reject(description + ": ring-linear activity needs a separate transfer rule")
        if representation == "wordwise" and isinstance(component, SBox):
            if sorted(component.table) != list(range(len(component.table))):
                reject(description + ": wordwise S-box propagation requires a bijection")
