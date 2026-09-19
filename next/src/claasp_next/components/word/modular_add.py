from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.graph import Component, Selection


@dataclass(frozen=True, slots=True, init=False)
class ModularAdd(Component):
    """Add word vectors component-wise modulo an explicit or power-of-two modulus.

    EXAMPLES::

        >>> from claasp_next.primitives.single_component_primitives import ModularAdd as AddPrimitive
        >>> AddPrimitive(4).evaluate(15, 2)
        1
    """

    modulus: int | None

    def __init__(
        self, component_inputs: Iterable[Selection], component_id: str | None = None,
        *, modulus: int | None = None,
    ) -> None:
        inputs = tuple(component_inputs)
        if len(inputs) < 2:
            raise ValueError("modular addition requires at least two inputs")
        inputs, output_type = require_word_inputs(inputs, "modular addition")
        if modulus is not None and (
            not isinstance(modulus, int) or isinstance(modulus, bool)
            or modulus <= 1 or modulus > 1 << output_type.domain.width
        ):
            raise ValueError("modulus must be an integer in (1, 2^width]")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        object.__setattr__(self, "modulus", modulus)
        Component.__post_init__(self)
