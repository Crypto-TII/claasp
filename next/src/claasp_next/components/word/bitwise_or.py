"""Typed component-wise Boolean OR."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class BitwiseOr(Component):
    """OR two or more equally typed word vectors component-wise."""

    def __init__(self, component_inputs: Iterable[PortLike], component_id: str | None = None) -> None:
        inputs = tuple(component_inputs)
        if len(inputs) < 2:
            raise ValueError("word OR requires at least two inputs")
        inputs, output_type = require_word_inputs(inputs, "word OR")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
