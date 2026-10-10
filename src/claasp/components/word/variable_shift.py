from dataclasses import dataclass

from claasp.components.algebraic._validation import normalize_inputs
from claasp.domains import Word
from claasp.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class VariableShift(Component):
    """Shift each word by an amount supplied as a one-unit word input.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import VariableShift
        >>> VariableShift().evaluate(0x81, 2)
        32
    """

    direction: str

    def __init__(
        self,
        component_input: PortLike,
        amount_input: PortLike,
        direction: str,
        component_id: str | None = None,
    ) -> None:
        inputs = normalize_inputs((component_input, amount_input))
        array_type = inputs[0].array_type
        amount_type = inputs[1].array_type
        if not isinstance(array_type.domain, Word) or not isinstance(amount_type.domain, Word):
            raise ValueError("variable shift requires Word-domain value and amount inputs")
        if amount_type.unit_count != 1:
            raise ValueError("variable shift amount must contain exactly one word")
        if direction not in ("left", "right"):
            raise ValueError("shift direction must be 'left' or 'right'")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", array_type)
        object.__setattr__(self, "direction", direction)
        Component.__post_init__(self)
