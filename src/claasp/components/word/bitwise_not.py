"""Typed component-wise Boolean complement."""

from dataclasses import dataclass

from claasp.components.word._validation import require_word_inputs
from claasp.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class BitwiseNot(Component):
    """Complement every bit in a vector of fixed-width words.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import BitwiseNot as NotPrimitive
        >>> NotPrimitive(4).evaluate(0b1010)
        5
    """

    def __init__(self, component_input: PortLike, component_id: str | None = None) -> None:
        inputs, output_type = require_word_inputs((component_input,), "word NOT")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
