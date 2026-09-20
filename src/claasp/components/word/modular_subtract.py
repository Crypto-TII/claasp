from collections.abc import Iterable
from dataclasses import dataclass

from claasp.components.word._validation import require_word_inputs
from claasp.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class ModularSubtract(Component):
    """Subtract word vectors from left to right modulo ``2^width``.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import ModularSubtract as SubtractPrimitive
        >>> SubtractPrimitive(4).evaluate(1, 2)
        15
    """

    def __init__(
        self, component_inputs: Iterable[PortLike], component_id: str | None = None
    ) -> None:
        inputs = tuple(component_inputs)
        if len(inputs) < 2:
            raise ValueError("modular subtraction requires at least two inputs")
        inputs, output_type = require_word_inputs(inputs, "modular subtraction")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
