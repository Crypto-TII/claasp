"""One-component data-dependent rotation function."""

from claasp_next.components import VariableRotate as VariableRotateComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class VariableRotate(Primitive):
    def __init__(self, bit_size: int = 8, amount_bit_size: int = 3, direction: int = 1) -> None:
        bit_size = positive(bit_size, "bit_size")
        positive(amount_bit_size, "amount_bit_size")
        super().__init__(
            "variable_rotate",
            {"input": ValueType(Word(bit_size), (1,)),
             "amount": ValueType(Word(amount_bit_size), (1,))},
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        self.set_output(self.add_component(VariableRotateComponent(
            self.input("input"), self.input("amount"),
            "right" if direction >= 0 else "left",
        )))


__all__ = ["VariableRotate"]
