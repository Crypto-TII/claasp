from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class Shift(Component):
    """Shift every selected word with zero fill and no wraparound.

    EXAMPLES::

        >>> from claasp_next.primitives.single_component_primitives import Shift as ShiftPrimitive
        >>> ShiftPrimitive(8, 1, "right").evaluate(0x81)
        64
    """

    amount: int
    direction: str

    def __init__(
        self,
        component_input: PortLike,
        amount: int,
        direction: str,
        component_id: str | None = None,
    ) -> None:
        inputs, output_type = require_word_inputs((component_input,), "shift")
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise TypeError("shift amount must be an integer")
        if amount < 0:
            raise ValueError("shift amount must be non-negative")
        if direction not in ("left", "right"):
            raise ValueError("shift direction must be 'left' or 'right'")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        object.__setattr__(self, "amount", amount)
        object.__setattr__(self, "direction", direction)
        Component.__post_init__(self)
