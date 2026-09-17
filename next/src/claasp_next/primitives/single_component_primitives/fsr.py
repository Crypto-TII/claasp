"""One-component feedback-register primitive."""

from claasp_next.components import FeedbackRegister, FeedbackRegisterParameters
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Fsr(Primitive):
    def __init__(
        self,
        register_size: int = 4,
        description=None,
        *,
        parameters: FeedbackRegisterParameters | None = None,
    ) -> None:
        register_size = positive(register_size, "register_size")
        parameters = FeedbackRegisterParameters.resolve(
            register_size, parameters, legacy_description=description,
        )
        super().__init__(
            "fsr", {"input": ValueType(parameters.domain, (parameters.unit_count,))},
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        self.set_output(self.add_component(FeedbackRegister(
            self.input("input"), parameters.registers, parameters.clocks,
        )))


__all__ = ["Fsr"]
