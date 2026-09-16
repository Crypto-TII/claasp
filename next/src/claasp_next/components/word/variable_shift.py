from dataclasses import dataclass

from claasp_next.components.algebraic._validation import normalize_inputs
from claasp_next.domains import Word
from claasp_next.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class VariableShift(Component):
    """Shift each word by an amount supplied as a one-unit word input."""

    direction: str

    def __init__(
        self,
        component_input: PortLike,
        amount_input: PortLike,
        direction: str,
        component_id: str | None = None,
    ) -> None:
        inputs = normalize_inputs((component_input, amount_input))
        value_type = inputs[0].value_type
        amount_type = inputs[1].value_type
        if not isinstance(value_type.domain, Word) or not isinstance(amount_type.domain, Word):
            raise ValueError("variable shift requires Word-domain value and amount inputs")
        if amount_type.unit_count != 1:
            raise ValueError("variable shift amount must contain exactly one word")
        if direction not in ("left", "right"):
            raise ValueError("shift direction must be 'left' or 'right'")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", value_type)
        object.__setattr__(self, "direction", direction)
        Component.__post_init__(self)
