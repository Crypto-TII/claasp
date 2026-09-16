from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class ModularMultiply(Component):
    """Multiply word vectors component-wise modulo an explicit modulus."""

    modulus: int

    def __init__(
        self,
        component_inputs: Iterable[PortLike],
        modulus: int | None = None,
        component_id: str | None = None,
    ) -> None:
        inputs = tuple(component_inputs)
        if len(inputs) < 2:
            raise ValueError("modular multiplication requires at least two inputs")
        inputs, output_type = require_word_inputs(inputs, "modular multiplication")
        word_modulus = 1 << output_type.domain.width
        if modulus is None:
            modulus = word_modulus
        if not isinstance(modulus, int) or isinstance(modulus, bool):
            raise TypeError("modulus must be an integer")
        if not 1 < modulus <= word_modulus:
            raise ValueError(f"modulus must be in 2..{word_modulus}")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        object.__setattr__(self, "modulus", modulus)
        Component.__post_init__(self)
