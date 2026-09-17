"""Primitive consisting of one feedback-register component."""

from claasp_next.components import (
    FeedbackRegister as FeedbackRegisterComponent,
    FeedbackRegisterParameters,
)
from claasp_next.graph import Primitive, PrimitiveKind, ValueType


class FeedbackRegister(Primitive):
    """Clock a register described by typed feedback parameters.

    The default is a four-bit Fibonacci register with feedback taps at
    positions 0 and 1. One clock changes ``1010`` into ``0101``.

    >>> f"{FeedbackRegister().evaluate(0b1010):04b}"
    '0101'

    Supply typed parameters for another register size, tap set, or clock
    count:

    >>> parameters = FeedbackRegisterParameters.from_taps(8, [0, 2, 3], clocks=2)
    >>> register = FeedbackRegister(parameters)
    >>> f"{register.evaluate(0b10110010):08b}"
    '11001011'
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
