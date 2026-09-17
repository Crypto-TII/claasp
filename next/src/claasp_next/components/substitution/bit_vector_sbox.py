"""Substitution of a group of individual bit units."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.graph import Component, PortLike, ValueType, as_selection
from claasp_next.domains import Bit
from claasp_next.components.substitution.lookup_table import LookupTable


@dataclass(frozen=True, slots=True, init=False)
class BitVectorSBox(Component):
    """Map one MSB-first bit vector through an integer lookup table."""

    table: tuple[int, ...]
    output_bit_size: int

    def __init__(
        self,
        component_input: PortLike,
        table: Iterable[int] | LookupTable,
        component_id: str | None = None,
        output_bit_size: int | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        if not isinstance(component_input.value_type.domain, Bit):
            raise ValueError("bit-vector S-box requires the Bit domain")
        width = component_input.value_type.unit_count
        if isinstance(table, LookupTable):
            lookup_table = table
            if lookup_table.input_bit_size != width:
                raise ValueError(
                    "lookup-table input width must match the selected bits"
                )
            if (
                output_bit_size is not None
                and output_bit_size != lookup_table.output_bit_size
            ):
                raise ValueError("output_bit_size conflicts with the lookup table")
        else:
            lookup_table = LookupTable(table, width, output_bit_size)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(
            self, "output_type", ValueType(Bit(), (lookup_table.output_bit_size,))
        )
        object.__setattr__(self, "table", lookup_table.values)
        object.__setattr__(self, "output_bit_size", lookup_table.output_bit_size)
        Component.__post_init__(self)
