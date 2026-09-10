from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.core import Component, Selection


@dataclass(frozen=True, slots=True, init=False)
class Rotate(Component):
    """Rotate every selected word left or right by a fixed distance."""

    amount: int
    direction: str

    def __init__(self, component_id: str, component_input: Selection, amount: int, direction: str) -> None:
        output_type = require_word_inputs((component_input,), "rotation")
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
