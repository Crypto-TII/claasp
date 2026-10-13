"""Lookup-table substitution over canonically encoded units."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp.components.substitution.lookup_table import LookupTable
from claasp.graph import Component, UnitArrayLike, as_selection
from claasp.unit_types import BinaryExtensionField, Bit, Word


@dataclass(frozen=True, slots=True, init=False)
class SBox(Component):
    """Apply one lookup table independently to every selected unit.

    The input and output retain the same unit type. This first representation is
    intended for finite, densely encoded domains such as bytes, words, and
    binary-extension-field elements.

    EXAMPLES::

        >>> from claasp.unit_types import Word
        >>> from claasp.primitives.single_component_primitives import SBox
        >>> SBox([3, 2, 1, 0], Word(2), unit_count=2).evaluate(0b0001)
        14
    """

    table: tuple[int, ...]

    def __init__(
        self,
        component_input: UnitArrayLike,
        table: Iterable[int] | LookupTable,
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        unit_type = component_input.array_type.unit_type
        if not isinstance(unit_type, (Bit, Word, BinaryExtensionField)):
            raise ValueError("S-box requires a densely encoded finite unit type")
        if isinstance(table, LookupTable):
            lookup_table = table
            if (
                lookup_table.input_bit_size != unit_type.encoded_bit_size
                or lookup_table.output_bit_size != unit_type.encoded_bit_size
            ):
                raise ValueError("lookup-table widths must match the S-box unit type")
        else:
            lookup_table = LookupTable(
                table, unit_type.encoded_bit_size, unit_type.encoded_bit_size
            )
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.array_type)
        object.__setattr__(self, "table", lookup_table.values)
        Component.__post_init__(self)
