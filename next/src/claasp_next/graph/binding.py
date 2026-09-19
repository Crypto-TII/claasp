"""Typed graph wiring that does not introduce semantic components."""

from dataclasses import dataclass
from enum import Enum

from claasp_next.graph.port import Port, Selection
from claasp_next.graph.value_type import ValueType


class BindingKind(str, Enum):
    """Classify structural transformations carried by graph edges.

    EXAMPLES::

        >>> BindingKind.PACK_BITS.value
        'pack_bits'
    """

    JOIN = "join"
    VIEW = "view"
    PACK_BITS = "pack_bits"
    UNPACK_BITS = "unpack_bits"


@dataclass(frozen=True, slots=True)
class ValueBinding:
    """Describe one typed wiring value derived from graph sources.

    EXAMPLES::

        >>> from claasp_next import Bit, Port, ValueType
        >>> source = Port("bits", ValueType(Bit(), (2,)))
        >>> binding = ValueBinding("view_0", BindingKind.VIEW, (source[:],), source.value_type)
        >>> binding.output.owner_id
        'view_0'
    """

    binding_id: str
    kind: BindingKind
    inputs: tuple[Selection, ...]
    output_type: ValueType
    word_width: int | None = None

    @property
    def output(self) -> Port:
        """Return the addressable output port created by this binding."""

        return Port(self.binding_id, self.output_type)


__all__ = ["BindingKind", "ValueBinding"]
