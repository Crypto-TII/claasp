"""Primitive consisting of one feedback-register component."""

from claasp_next.components import (
    FeedbackRegister as FeedbackRegisterComponent,
    FeedbackRegisterParameters,
)
from claasp_next.graph import Primitive, PrimitiveKind, ValueType


class FeedbackRegister(Primitive):
    """Clock a register described by typed feedback parameters.

    >>> FeedbackRegister().evaluate(0b1010)
    5
    """

    def __init__(self, parameters: FeedbackRegisterParameters | None = None) -> None:
        parameters = (
            FeedbackRegisterParameters.from_taps(4, [0, 1])
            if parameters is None
            else parameters
        )
        if not isinstance(parameters, FeedbackRegisterParameters):
            raise TypeError("parameters must be FeedbackRegisterParameters")
        super().__init__(
            "feedback_register",
            {"input": ValueType(parameters.domain, (parameters.unit_count,))},
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        output = self.add_component(
            FeedbackRegisterComponent(
                self.input("input"), parameters.registers, parameters.clocks
            )
        )
        self.set_output(output)


__all__ = ["FeedbackRegister"]
