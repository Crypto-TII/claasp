from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.components.word._validation import require_word_inputs
from claasp_next.graph import Component, PortLike


@dataclass(frozen=True, slots=True, init=False)
class IDEAMultiply(Component):
    """IDEA multiplication modulo ``2^width + 1`` with zero encoding ``2^width``.

    EXAMPLES::

        >>> from claasp_next.primitives.single_component_primitives import IDEAMultiply
        >>> IDEAMultiply(4).evaluate(3, 5)
        15
    """

    inverse_inputs: tuple[int, ...]

    def __init__(
        self,
        component_inputs: Iterable[PortLike],
        component_id: str | None = None,
        *,
        inverse_inputs: Iterable[int] = (),
    ) -> None:
        inputs = tuple(component_inputs)
        if len(inputs) < 2:
            raise ValueError("IDEA multiplication requires at least two inputs")
        inputs, output_type = require_word_inputs(inputs, "IDEA multiplication")
        inverse_inputs = tuple(inverse_inputs)
        if len(set(inverse_inputs)) != len(inverse_inputs) or any(
            not isinstance(index, int) or isinstance(index, bool)
            or index not in range(len(inputs)) for index in inverse_inputs
        ):
            raise ValueError("inverse IDEA input indexes must be unique valid input positions")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "output_type", output_type)
        object.__setattr__(self, "inverse_inputs", inverse_inputs)
        Component.__post_init__(self)
