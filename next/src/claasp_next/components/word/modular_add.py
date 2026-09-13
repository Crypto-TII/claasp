from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.graph import Component, Selection


@dataclass(frozen=True, slots=True, init=False)
class ModularAdd(Component):
    """Add word vectors component-wise modulo ``2^width``."""

    def __init__(self, component_inputs: Iterable[Selection], component_id: str | None = None) -> None:
        inputs = tuple(component_inputs)
        if len(inputs) < 2:
            raise ValueError("modular addition requires at least two inputs")
        inputs, output_type = require_word_inputs(inputs, "modular addition")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
