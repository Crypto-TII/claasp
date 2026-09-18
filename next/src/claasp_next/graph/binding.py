"""Typed graph wiring that does not introduce semantic components."""

from dataclasses import dataclass
from enum import Enum

from claasp_next.graph.port import Port, Selection
from claasp_next.graph.value_type import ValueType


class BindingKind(str, Enum):
    """Structural transformations carried by graph edges."""

    JOIN = "join"
    VIEW = "view"
    PACK_BITS = "pack_bits"
    UNPACK_BITS = "unpack_bits"


@dataclass(frozen=True, slots=True)
class ValueBinding:
    """One typed, addressable wiring value derived from existing sources."""

    binding_id: str
    kind: BindingKind
    inputs: tuple[Selection, ...]
    output_type: ValueType
    word_width: int | None = None

    @property
    def output(self) -> Port:
        return Port(self.binding_id, self.output_type)


__all__ = ["BindingKind", "ValueBinding"]
