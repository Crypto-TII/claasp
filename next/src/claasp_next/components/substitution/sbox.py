"""Lookup-table substitution over canonically encoded units."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.core import Component, PortLike, as_selection
from claasp_next.domains import BinaryExtensionField, Bit, Word


@dataclass(frozen=True, slots=True, init=False)
class SBox(Component):
    """Apply one lookup table independently to every selected unit.

    The input and output retain the same domain. This first representation is
    intended for finite, densely encoded domains such as bytes, words, and
    binary-extension-field elements.
    """

    table: tuple[int, ...]

    def __init__(
        self,
        component_input: PortLike,
        table: Iterable[int],
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        domain = component_input.value_type.domain
        if not isinstance(domain, (Bit, Word, BinaryExtensionField)):
            raise ValueError("S-box requires a densely encoded finite domain")
        frozen_table = tuple(table)
        expected_size = 1 << domain.encoded_bit_size
        if len(frozen_table) != expected_size:
            raise ValueError(f"S-box table must contain {expected_size} entries")
        for value in frozen_table:
            domain.validate(value)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.value_type)
        object.__setattr__(self, "table", frozen_table)
        Component.__post_init__(self)
