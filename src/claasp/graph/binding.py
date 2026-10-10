"""Typed graph wiring that does not introduce semantic components."""

from dataclasses import dataclass
from enum import Enum

from claasp.graph.array_type import ArrayType
from claasp.graph.port import Port, Selection


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

        >>> from claasp import Port, ArrayType
        >>> from claasp.domains import Bit
        >>> source = Port("bits", ArrayType(Bit(), (2,)))
        >>> binding = ValueBinding("view_0", BindingKind.VIEW, (source[:],), source.array_type)
        >>> binding.output.owner_id
        'view_0'
    """

    binding_id: str
    kind: BindingKind
    inputs: tuple[Selection, ...]
    output_type: ArrayType
    word_width: int | None = None

    @property
    def output(self) -> Port:
        """Return the addressable output port created by this binding."""

        return Port(self.binding_id, self.output_type)


__all__ = ["BindingKind", "ValueBinding"]
