"""One-component feedback-register primitive."""

from claasp_next.components import FeedbackRegister, FeedbackRegisterParameters
from claasp_next.graph import Primitive, PrimitiveKind, ValueType


class Fsr(Primitive):
    """Clock a feedback register described by typed parameters."""

    def __init__(self, parameters: FeedbackRegisterParameters | None = None) -> None:
        if parameters is None:
            parameters = FeedbackRegisterParameters.from_taps(4, [0, 1])
        if not isinstance(parameters, FeedbackRegisterParameters):
            raise TypeError("parameters must be FeedbackRegisterParameters")
        super().__init__(
            "fsr", {"input": ValueType(parameters.domain, (parameters.unit_count,))},
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        self.set_output(self.add_component(FeedbackRegister(
            self.input("input"), parameters.registers, parameters.clocks,
        )))


__all__ = ["Fsr"]
