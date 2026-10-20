from collections.abc import Iterable
from dataclasses import dataclass

from claasp.components.algebraic._validation import (
    normalize_operand_arguments,
    require_homogeneous_inputs,
)
from claasp.graph import Component, UnitArrayLike
from claasp.unit_types import Bit, Word


@dataclass(frozen=True, slots=True, init=False)
class Xor(Component):
    """XOR word vectors component-wise.

    Pass inputs as separate arguments, or as one iterable.
    ``component_id`` can be supplied by keyword.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import Xor as XorPrimitive
        >>> XorPrimitive().evaluate(0b1010, 0b0011)
        9
    """

    def __init__(
        self,
        *component_inputs: UnitArrayLike | Iterable[UnitArrayLike] | str,
        component_id: str | None = None,
    ) -> None:
        inputs, component_id = normalize_operand_arguments(component_inputs, component_id)
        if len(inputs) < 2:
            raise ValueError("word XOR requires at least two inputs")
        output_type = require_homogeneous_inputs(inputs, "XOR")
        if not isinstance(output_type.unit_type, (Bit, Word)):
            raise ValueError("XOR requires the Bit or Word unit_type")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
