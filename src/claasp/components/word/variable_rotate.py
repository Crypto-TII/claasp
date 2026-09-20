from dataclasses import dataclass

from claasp.components.algebraic._validation import normalize_inputs
from claasp.domains import Word
from claasp.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class VariableRotate(Component):
    """Rotate each word by an amount supplied as a one-unit word input.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import VariableRotate
        >>> VariableRotate().evaluate(0x81, 2)
        96
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
        value_type = inputs[0].value_type
        amount_type = inputs[1].value_type
        if not isinstance(value_type.domain, Word) or not isinstance(amount_type.domain, Word):
            raise ValueError("variable rotation requires Word-domain value and amount inputs")
        if amount_type.unit_count != 1:
            raise ValueError("variable rotation amount must contain exactly one word")
        if direction not in ("left", "right"):
            raise ValueError("rotation direction must be 'left' or 'right'")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", value_type)
        object.__setattr__(self, "direction", direction)
        Component.__post_init__(self)
