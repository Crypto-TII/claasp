"""Typed metadata for primitive boundaries."""

from dataclasses import dataclass, replace
from enum import Enum

from claasp_next.graph.value_type import ValueType


class PrimitiveKind(str, Enum):
    """Mathematical interface exposed by a primitive graph."""

    FUNCTION = "function"
    PERMUTATION = "permutation"
    BLOCK_FUNCTION = "block_function"
    BLOCK_CIPHER = "block_cipher"
    TWEAKABLE_BLOCK_CIPHER = "tweakable_block_cipher"


class InputVisibility(str, Enum):
    """Default confidentiality of a primitive input in a study."""

    PUBLIC = "public"
    SECRET = "secret"


@dataclass(frozen=True, slots=True)
class PrimitiveInput:
    """Type, semantic role, and default visibility of one graph input."""

    value_type: ValueType
    role: str = "data"
    visibility: InputVisibility = InputVisibility.PUBLIC

    def __post_init__(self) -> None:
        if not isinstance(self.value_type, ValueType):
            raise TypeError("value_type must be a ValueType")
        if not isinstance(self.role, str) or not self.role:
            raise ValueError("input role must be a non-empty string")
        if not isinstance(self.visibility, InputVisibility):
            object.__setattr__(self, "visibility", InputVisibility(self.visibility))

    @property
    def is_secret(self) -> bool:
        return self.visibility is InputVisibility.SECRET

    def with_visibility(self, visibility: InputVisibility | str) -> "PrimitiveInput":
        return replace(self, visibility=InputVisibility(visibility))


def public_input(value_type: ValueType, *, role: str = "data") -> PrimitiveInput:
    """Describe a public primitive input."""

    return PrimitiveInput(value_type, role, InputVisibility.PUBLIC)


def secret_input(value_type: ValueType, *, role: str = "key") -> PrimitiveInput:
    """Describe a secret primitive input."""

    return PrimitiveInput(value_type, role, InputVisibility.SECRET)


def infer_primitive_kind(input_descriptors: dict[str, PrimitiveInput]) -> PrimitiveKind:
    """Conservatively infer a kind when source code does not declare one."""

    names = set(input_descriptors)
    if any(item.is_secret for item in input_descriptors.values()):
        if names & {"tweak", "input_tweak"}:
            return PrimitiveKind.TWEAKABLE_BLOCK_CIPHER
        if "plaintext" in names:
            return PrimitiveKind.BLOCK_CIPHER
        return PrimitiveKind.BLOCK_FUNCTION
    if names == {"state"} or names == {"input_state"}:
        return PrimitiveKind.PERMUTATION
    return PrimitiveKind.FUNCTION


LEGACY_KIND_NAMES = {
    "block_cipher": PrimitiveKind.BLOCK_CIPHER,
    "tweakable_block_cipher": PrimitiveKind.TWEAKABLE_BLOCK_CIPHER,
    "permutation": PrimitiveKind.PERMUTATION,
    "hash_function": PrimitiveKind.FUNCTION,
    "stream_cipher": PrimitiveKind.BLOCK_FUNCTION,
}
