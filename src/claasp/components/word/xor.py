from dataclasses import dataclass

from claasp.components.algebraic._validation import normalize_inputs, require_homogeneous_inputs
from claasp.domains import Bit, Word
from claasp.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class Xor(Component):
    """XOR word vectors component-wise.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import Xor as XorPrimitive
        >>> XorPrimitive().evaluate(0b1010, 0b0011)
        9
    """

    def __init__(self, *component_inputs: PortLike, component_id: str | None = None) -> None:
        if component_inputs and isinstance(component_inputs[-1], str):
            if component_id is not None:
                raise TypeError("component_id was supplied twice")
            *component_inputs, component_id = component_inputs
        if len(component_inputs) == 1 and not isinstance(component_inputs[0], PortLike):
            component_inputs = tuple(component_inputs[0])
        inputs = normalize_inputs(tuple(component_inputs))
        if len(inputs) < 2:
            raise ValueError("word XOR requires at least two inputs")
        output_type = require_homogeneous_inputs(inputs, "XOR")
        if not isinstance(output_type.domain, (Bit, Word)):
            raise ValueError("XOR requires the Bit or Word domain")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
