"""Substitution of a group of individual bit units."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.graph import Component, PortLike, ValueType, as_selection
from claasp_next.domains import Bit


@dataclass(frozen=True, slots=True, init=False)
class BitVectorSBox(Component):
    """Map one MSB-first bit vector through an integer lookup table."""

    table: tuple[int, ...]
    output_bit_size: int

    def __init__(
        self,
        component_input: PortLike,
        table: Iterable[int],
        component_id: str | None = None,
        output_bit_size: int | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        if not isinstance(component_input.value_type.domain, Bit):
            raise ValueError("bit-vector S-box requires the Bit domain")
        width = component_input.value_type.unit_count
        if output_bit_size is None:
            output_bit_size = width
        if not isinstance(output_bit_size, int) or isinstance(output_bit_size, bool) or output_bit_size <= 0:
            raise ValueError("output_bit_size must be a positive integer")
        frozen_table = tuple(table)
        if len(frozen_table) != 1 << width:
            raise ValueError(f"bit-vector S-box table must contain {1 << width} entries")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << output_bit_size)
            for value in frozen_table
        ):
            raise ValueError(f"bit-vector S-box outputs must fit in {output_bit_size} bits")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", ValueType(Bit(), (output_bit_size,)))
        object.__setattr__(self, "table", frozen_table)
        object.__setattr__(self, "output_bit_size", output_bit_size)
        Component.__post_init__(self)
