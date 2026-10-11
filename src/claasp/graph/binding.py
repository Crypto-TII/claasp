"""Typed graph wiring that does not introduce semantic components."""

from dataclasses import dataclass
from enum import Enum

from claasp.graph.unit_array import Selection, UnitArray
from claasp.graph.unit_array_type import UnitArrayType


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

        >>> from claasp import UnitArray, UnitArrayType
        >>> from claasp.unit_types import Bit
        >>> source = UnitArray("bits", UnitArrayType(Bit(), (2,)))
        >>> binding = ValueBinding("view_0", BindingKind.VIEW, (source[:],), source.array_type)
        >>> binding.output.source_id
        'view_0'
    """

    binding_id: str
    kind: BindingKind
    inputs: tuple[Selection, ...]
    output_type: UnitArrayType
    word_width: int | None = None

    @property
    def output(self) -> UnitArray:
        """Return the addressable output unit array created by this binding."""

        return UnitArray(self.binding_id, self.output_type)


__all__ = ["BindingKind", "ValueBinding"]
