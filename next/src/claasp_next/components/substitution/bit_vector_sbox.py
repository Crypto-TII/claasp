"""Substitution of a group of individual bit units."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.core import Component, PortLike, ValueType, as_selection
from claasp_next.domains import Bit


@dataclass(frozen=True, slots=True, init=False)
class BitVectorSBox(Component):
    """Map one MSB-first bit vector through an integer lookup table."""

    table: tuple[int, ...]

    def __init__(
        self,
        component_input: PortLike,
        table: Iterable[int],
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        if not isinstance(component_input.value_type.domain, Bit):
            raise ValueError("bit-vector S-box requires the Bit domain")
        width = component_input.value_type.unit_count
        frozen_table = tuple(table)
        if len(frozen_table) != 1 << width:
            raise ValueError(f"bit-vector S-box table must contain {1 << width} entries")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << width)
            for value in frozen_table
        ):
            raise ValueError(f"bit-vector S-box outputs must fit in {width} bits")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", ValueType(Bit(), (width,)))
        object.__setattr__(self, "table", frozen_table)
        Component.__post_init__(self)
