"""One-component Xoodoo theta permutation."""

from claasp_next.components.permutation import xoodoo_theta
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class ThetaXoodoo(Primitive):
    def __init__(self, bit_size: int = 384) -> None:
        super().__init__(
            "theta_xoodoo", {"input": ValueType(Bit(), (positive(bit_size, "bit_size"),))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(self.add_component(xoodoo_theta(self.input("input"))))


__all__ = ["ThetaXoodoo"]
