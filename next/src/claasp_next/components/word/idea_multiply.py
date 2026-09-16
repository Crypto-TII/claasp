from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class IDEAMultiply(Component):
    """IDEA multiplication modulo ``2^width + 1`` with zero encoding ``2^width``."""

    def __init__(self, component_inputs: Iterable[PortLike], component_id: str | None = None) -> None:
        inputs = tuple(component_inputs)
        if len(inputs) < 2:
            raise ValueError("IDEA multiplication requires at least two inputs")
        inputs, output_type = require_word_inputs(inputs, "IDEA multiplication")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
