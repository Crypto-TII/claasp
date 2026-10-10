"""Typed metadata for primitive boundaries."""

from dataclasses import dataclass, replace
from enum import Enum

from claasp.graph.value_type import ValueType


class PrimitiveKind(str, Enum):
    """Classify the mathematical interface exposed by a primitive graph.

    EXAMPLES::

        >>> PrimitiveKind.BLOCK_CIPHER.value
        'block_cipher'
    """

    FUNCTION = "function"
    PERMUTATION = "permutation"
    BLOCK_FUNCTION = "block_function"
    BLOCK_CIPHER = "block_cipher"
    TWEAKABLE_BLOCK_CIPHER = "tweakable_block_cipher"


class InputVisibility(str, Enum):
    """Describe default confidentiality of a primitive input.

    EXAMPLES::

        >>> InputVisibility.SECRET.value
        'secret'
    """

    PUBLIC = "public"
    SECRET = "secret"


@dataclass(frozen=True, slots=True)
class PrimitiveInput:
    """Record type, semantic role, and visibility of one graph input.

    EXAMPLES::

        >>> from claasp import Bit, ValueType
        >>> descriptor = PrimitiveInput(ValueType(Bit(), (8,)), "key", InputVisibility.SECRET)
        >>> (descriptor.role, descriptor.is_secret)
        ('key', True)
        >>> descriptor.with_visibility("public").is_secret
        False
    """

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
        """Return whether the default study visibility is secret."""

        return self.visibility is InputVisibility.SECRET

    def with_visibility(self, visibility: InputVisibility | str) -> "PrimitiveInput":
        """Return an immutable copy with explicitly changed visibility."""

        return replace(self, visibility=InputVisibility(visibility))


def public_input(value_type: ValueType, *, role: str = "data") -> PrimitiveInput:
    """Describe a public primitive input.

    EXAMPLES::

        >>> from claasp import Bit, ValueType
        >>> public_input(ValueType(Bit(), (1,))).visibility.value
        'public'
    """

    return PrimitiveInput(value_type, role, InputVisibility.PUBLIC)


def secret_input(value_type: ValueType, *, role: str = "key") -> PrimitiveInput:
    """Describe a secret primitive input.

    EXAMPLES::

        >>> from claasp import Bit, ValueType
        >>> secret_input(ValueType(Bit(), (1,))).is_secret
        True
    """

    return PrimitiveInput(value_type, role, InputVisibility.SECRET)


def infer_primitive_kind(input_descriptors: dict[str, PrimitiveInput]) -> PrimitiveKind:
    """Conservatively infer a kind when source code does not declare one."""

    names = set(input_descriptors)
    if any(item.is_secret for item in input_descriptors.values()):
        if names & {"tweak", "input_tweak"}:
            return PrimitiveKind.TWEAKABLE_BLOCK_CIPHER
        if names & {"plaintext", "message"}:
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
