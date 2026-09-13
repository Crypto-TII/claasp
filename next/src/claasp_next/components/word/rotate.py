from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class Rotate(Component):
    """Rotate every selected word left or right by a fixed distance."""

    amount: int
    direction: str

    def __init__(
        self,
        component_input: PortLike,
        amount: int,
        direction: str,
        component_id: str | None = None,
    ) -> None:
        inputs, output_type = require_word_inputs((component_input,), "rotation")
        component_input = inputs[0]
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise TypeError("rotation amount must be an integer")
        if direction not in ("left", "right"):
            raise ValueError("rotation direction must be 'left' or 'right'")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", output_type)
        object.__setattr__(self, "amount", amount % output_type.domain.width)
        object.__setattr__(self, "direction", direction)
        Component.__post_init__(self)
