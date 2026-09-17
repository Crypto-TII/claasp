"""One-component Sigma linear function."""

from claasp_next.components.permutation import sigma
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Sigma(Primitive):
    def __init__(self, bit_size: int = 8, rotation_amounts_parameter=None) -> None:
        bit_size = positive(bit_size, "bit_size")
        amounts = [1, 2] if rotation_amounts_parameter is None else rotation_amounts_parameter
        super().__init__("sigma", {"input": ValueType(Bit(), (bit_size,))}, kind=PrimitiveKind.FUNCTION)
        self.add_round()
        self.set_output(self.add_component(sigma(self.input("input"), amounts)))


__all__ = ["Sigma"]
